from datetime import datetime, timezone, timedelta

import jwt
from passlib.context import CryptContext

from .server import Request, Response

#####
# User credentials
#####


class BaseUserCheck:
    crypt_context = CryptContext(["pbkdf2_sha256"])

    def __init__(self):
        pass

    def has_userid(self, userid: str) -> bool:
        return False

    def get_hash(self, userid: str) -> str:
        return ""

    def check(self, userid: str, password: str) -> str:
        try:
            if self.crypt_context.verify(password, self.get_hash(userid)):
                return userid
        except:
            pass
        return None


class DictUserCheck(BaseUserCheck):
    def __init__(self, passwords: dict):
        self.passwords = passwords

    def has_userid(self, userid: str) -> bool:
        return userid in self.passwords

    def get_hash(self, userid: str) -> str:
        return self.passwords.get(userid, "")


class TokenCheck(BaseUserCheck):
    def __init__(self, tokens: dict):
        self.tokens = {t: u for u, t in tokens.items()}

    def has_userid(self, userid: str) -> bool:
        return userid in self.tokens.values()

    def check(self, token: str):
        return self.tokens.get(token)


#####
# Authentication
#####


class BaseAuth:
    def __init__(
        self,
        header: str = "Authorization",
        scheme: str | None = None,
        except_paths: list[str] | None = None,
        except_hosts: list[str] | None = None,
        user_check: BaseUserCheck | None = None,
    ):
        if except_paths is None:
            except_paths = []
        if except_hosts is None:
            except_hosts = []

        self.header = header
        self.scheme = scheme.lower() if scheme else None
        self.except_paths = except_paths
        self.except_hosts = except_hosts

        self.user_check = user_check

    def _auth_user_check(self, *args):
        return self.user_check.check(*args)

    def error_401(self):
        return Response(status_code=401)

    def error_403(self):
        return Response(status_code=403)

    def _get_auth_args(self, auth):
        return (auth,)

    def __call__(self, req: Request):
        if req.path in self.except_paths:
            return None
        if req.client_addr[0] in self.except_hosts:
            return None
        auth = req.headers.get(self.header)
        if not auth:
            return self.error_401()
        if self.header == "Authorization":
            if " " not in auth:
                return self.error_401()
            scheme, auth = auth.split(" ", 1)
            if scheme.lower() != self.scheme:
                return self.error_401()
        req.g.userid = self._auth_user_check(*self._get_auth_args(auth))
        if not req.g.userid:
            return self.error_403()


class BasicAuth(BaseAuth):
    def __init__(
        self,
        except_paths: list[str] | None = None,
        except_hosts: list[str] | None = None,
        user_check: BaseUserCheck | None = None,
        realm: str="Local",
    ):
        super().__init__(
            header="Authorization",
            scheme="Basic",
            except_paths=except_paths,
            except_hosts=except_hosts,
            user_check=user_check,
        )
        self.realm = realm

    def _get_auth_args(self, auth):
        import binascii

        return binascii.a2b_base64(auth).decode("utf-8").split(":", 1)

    def error_401(self):
        return Response(status_code=401, headers={"WWW-Authenticate": f"Basic realm={self.realm}, charset=utf-8"})


class TokenAuth(BaseAuth):
    def __init__(
        self,
        except_paths: list[str] | None = None,
        except_hosts: list[str] | None = None,
        user_check: BaseUserCheck | None = None,
    ):
        super().__init__(
            header="Authorization",
            scheme="Bearer",
            except_paths=except_paths,
            except_hosts=except_hosts,
            user_check=user_check,
        )


class JwtAuth(BaseAuth):
    def __init__(
        self,
        secret: str | bytes,
        token_expire: timedelta = timedelta(hours=4),
        except_paths: list[str] | None = None,
        except_hosts: list[str] | None = None,
        user_check: BaseUserCheck | None = None,
    ):
        super().__init__(
            header="Authorization",
            scheme="Bearer",
            except_paths=except_paths,
            except_hosts=except_hosts,
            user_check=user_check,
        )

        self.secret = secret
        self.token_expire = token_expire

        self.valid_tokens = set()

    def _auth_user_check(self, userid: str):
        return userid if self.user_check.has_userid(userid) else None

    def to_token(self, userid: str) -> str:
        return jwt.encode(
            {
                "userid": userid,
                "iat": datetime.now(timezone.utc),
            },
            self.secret,
            algorithm="HS256",
        )

    def from_token(self, token: str) -> tuple[str, datetime]:
        userid = ""
        iat = datetime.min.replace(tzinfo=timezone.utc)
        if token:
            data = jwt.decode(token, self.secret, algorithms=["HS256"])
            userid = data.get("userid", "")
            if "iat" in data:
                iat = datetime.fromtimestamp(data["iat"], timezone.utc)
        return userid, iat

    def _get_auth_args(self, token):
        if not token in self.valid_tokens:
            return (None,)
        userid, iat = self.from_token(token)
        if iat < datetime.now(timezone.utc) - self.token_expire:
            return (None,)
        return (userid,)

    def login(self, req: Request):
        userid = ""
        password = None
        if req.json:
            userid = req.json.get("userid", "")
            password = req.json.get("password", None)

        if password and self.user_check.check(userid, password):
            token = self.to_token(userid)
            self.valid_tokens.add(token)
            return {
                "userid": userid,
                "token": token,
                "expires": int(self.token_expire.total_seconds()),
            }
        return self.error_401()

    def logout(self, req: Request):
        auth = req.headers.get(self.header)
        if not auth:
            return self.error_401()
        if " " not in auth:
            return self.error_401()
        scheme, token = auth.split(" ", 1)
        if scheme.lower() != self.scheme:
            return self.error_401()
        if token in self.valid_tokens:
            self.valid_tokens.remove(token)
        return {"token": None}


#####
# Run as script: Generate password hash
#####

if __name__ == "__main__":
    import getpass

    userid = input("User ID: ")
    hash = BaseUserCheck.crypt_context.hash(getpass.getpass("Password: "))
    print(f'{userid} = "{hash}"')
