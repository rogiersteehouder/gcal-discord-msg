from datetime import datetime, timezone, timedelta
from random import randbytes
from urllib.parse import urlencode

import jwt

from .server import app, Request, Response
from .jinja import StringTemplateResponse
from .auth import BaseUserCheck

#####
# Browser authentication
#####

class LoginAuth:
    def __init__(
        self,
        secret: str | bytes,
        token_expire: timedelta = timedelta(hours=4),
        except_paths: list[str] | None = None,
        except_hosts: list[str] | None = None,
        user_check: BaseUserCheck | None = None,
    ):
        if except_paths is None:
            except_paths = []
        if except_hosts is None:
            except_hosts = []
        except_paths.extend(["/login", "/logout", "/base.css"])

        self.secret = secret
        self.token_expire = token_expire

        self.except_paths = except_paths
        self.except_hosts = except_hosts

        self.user_check = user_check

        self.valid_tokens = set()

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

    def set_cookie(self, req: Request, token: str):
        if token:
            expires = None
        else:
            expires = "Thu, 01 Jan 1970 00:00:01 GMT"

        @req.after_request
        def _update_cookie(req, resp):
            resp.set_cookie(
                "auth_token", token, path="/", http_only=True, expires=expires
            )
            return resp

    def get_cookie(self, req: Request) -> str:
        return req.cookies.get("auth_token", "")

    def auth(self, req: Request) -> bool:
        if req.path in self.except_paths:
            return True
        if req.client_addr[0] in self.except_hosts:
            return True
        token = self.get_cookie(req)
        if not token in self.valid_tokens:
            return False
        userid, iat = self.from_token(token)
        req.g.userid = userid
        if iat < datetime.now(timezone.utc) - self.token_expire:
            return False
        return True

    def __call__(self, req: Request):
        if not self.auth(req):
            return Response.redirect("/login?{}".format(urlencode({"next": req.url})))

    def redirect_to_next(self, req: Request, default: str = "/"):
        url = req.args.get("next", default)
        if not url.startswith("/"):
            url = default
        return Response.redirect(url)

    def login(self, req: Request) -> bool:
        userid = ""
        password = None
        if req.form:
            userid = req.form.get("userid", "")
            password = req.form.get("password", None)

        if not self.user_check.check(userid, password):
            return False

        req.g.userid = userid
        token = self.to_token(userid)
        self.valid_tokens.add(token)
        self.set_cookie(req, token)
        return True

    def logout(self, req: Request):
        token = self.get_cookie(req)
        if token in self.valid_tokens:
            self.valid_tokens.remove(token)
        if "auth_token" in req.cookies:
            self.set_cookie(req, "")

login_auth = LoginAuth(randbytes(16))

app.before_request(login_auth)

@app.route("/login", methods=["GET", "POST"], name="login")
def login(req: Request):
    success_messages = []
    error_messages = []

    if login_auth.login(req):
        if "next" in req.args:
            return login_auth.redirect_to_next(req)
        success_messages.append("You have logged in.")
    elif req.method == "POST":
        error_messages.append('Wrong userid or password. Please try again.')
    elif hasattr(req.g, "userid"):
        error_messages.append("Your login session expired.")
    elif "logout" in req.args.getlist("from"):
        success_messages.append("You have logged out.")

    return StringTemplateResponse("""{% extends 'base.html.j2' %}
{% block title %}Login{% endblock %}
{% block description %}Login page{% endblock %}
{% block main %}
{% for msg in success_messages %}
<section class="success"><p>{{ msg }}</p></section>
{% endfor %}
{% for msg in error_messages %}
<section class="error"><p>{{ msg }}</p></section>
{% endfor %}
<section>
	<form method="post">
	<dl class="form">
		<dt><label for="userid">User ID</label></dt>
		<dd><input type="text" id="userid" name="userid" value="{{ userid }}" /></dd>
		<dt><label for="password">Password</label></dt>
		<dd><input type="password" id="password" name="password" /></dd>
		<dd><button type="submit">Login</button></dd>
	</dl>
	</form>
</section>
{% endblock %}
""", {
    "request": req,
    "userid": getattr(req.g, "userid", ""),
    "success_messages": success_messages,
    "error_messages": error_messages,
})

@app.route("/logout", methods=["GET"], name="logout")
def logout(req: Request):
    login_auth.logout(req)
    return Response.redirect("/login?from=logout")