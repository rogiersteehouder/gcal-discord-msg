"""
Los Hoes

Web microserver for quick web API's or a web interface.

Heavily based on Microdot (https://microdot.readthedocs.io/)
"""

import errno
import json
import re
import socket
import ssl
from datetime import datetime
from http import HTTPStatus
from pathlib import Path
from traceback import print_exception
from urllib.parse import parse_qs

from typing import Any, Iterable, Callable, Type, Self

from icecream import ic

#####
# Support functions and classes
#####


class NoCaseDict(dict):
    """A subclass of dictionary that holds case-insensitive keys."""

    def __init__(self, initial_dict: dict = None):
        super().__init__(initial_dict or {})
        self.keymap = {k.casefold(): k for k in self.keys() if k.casefold() != k}

    def __setitem__(self, key, value):
        kl = key.casefold()
        key = self.keymap.get(kl, key)
        if kl != key:
            self.keymap[kl] = key
        super().__setitem__(key, value)

    def __getitem__(self, key):
        kl = key.casefold()
        return super().__getitem__(self.keymap.get(kl, kl))

    def __delitem__(self, key):
        kl = key.casefold()
        super().__delitem__(self.keymap.get(kl, kl))

    def __contains__(self, key):
        kl = key.casefold()
        return self.keymap.get(kl, kl) in self.keys()

    def get(self, key, default=None):
        kl = key.casefold()
        return super().get(self.keymap.get(kl, kl), default)


class MultiDict(dict):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def __setitem__(self, key, value):
        if key not in self:
            super().__setitem__(key, [])
        super().__getitem__(key).append(value)

    def __getitem__(self, key):
        return super().__getitem__(key)[0]

    def get(self, key, default=None):
        try:
            return self[key]
        except KeyError:
            return default

    def getlist(self, key):
        try:
            return super().__getitem__(key)
        except KeyError:
            return []


class Status:
    def __init__(self):
        self.http_status = HTTPStatus
        for x in HTTPStatus:
            self.status_codes = {x.value: x.name for x in HTTPStatus}

    def get(self, status_code: int):
        try:
            return getattr(self.http_status, self.status_codes[status_code])
        except KeyError:
            return None

    def __getattr__(self, attr: Any):
        return getattr(self.http_status, attr)


status = Status()


#####
# Errors
#####


class HTTPException(Exception):
    def __init__(self, status_code: int, reason: str | None = None):
        self.status_code = status_code
        self.reason = reason or status.get(status_code).phrase

    def __repr__(self):
        return "HTTPException: {}".format(self.status_code)


#####
# Request
#####


class Request:
    """Request object"""

    max_content_length = 16 * 1024
    max_body_length = 16 * 1024
    max_readline = 2 * 1024
    socket_read_timeout = 1.0

    class G:
        pass

    def __init__(
        self,
        app: "Server",
        client_addr: tuple[str, int],
        method: str,
        url: str,
        http_version: str,
        headers: dict,
        body: bytes = None,
        stream=None,
    ):
        self.app = app
        self.client_addr = client_addr
        self.method = method
        self.url = url
        self.path = url
        self.query_string = None
        self.args = MultiDict()
        self.headers = headers
        self.cookies = {}
        self.content_length = 0
        self.content_type = None
        self.charset = "utf-8"
        self.g = self.G()

        self.http_version = http_version
        if "?" in self.path:
            self.path, self.query_string = self.path.split("?", 1)
            self.args = self._parse_urlencoded(self.query_string)
        if self.path != "/":
            self.path = self.path.rstrip("/")

        if "Content-Length" in self.headers:
            self.content_length = int(self.headers["Content-Length"])
        if "Content-Type" in self.headers:
            parts = self.headers["Content-Type"].split(";")
            self.content_type = parts[0]
            for part in parts[1:]:
                k, v = part.split("=", 1)
                if k.strip() == "charset":
                    self.charset = v.strip()
        if "Cookie" in self.headers:
            for cookie in self.headers["Cookie"].split(";"):
                name, value = cookie.strip().split("=", 1)
                self.cookies[name] = value

        self._stream = stream
        self._body = body
        self._json = None
        self._form = None
        self.after_request_handlers = []

    def __repr__(self):
        return f"<Request: {self.method} {self.url} >"

    @classmethod
    def create(cls, app: "Server", client_stream, client_addr: tuple[str, int]):
        """Create a request object from an icoming http request"""
        line = cls._safe_readline(client_stream).strip()
        try:
            line = line.decode()
        except UnicodeDecodeError:
            ic(line)
            raise
        if not line:
            return None
        method, url, http_version = line.split()
        http_version = http_version.split("/", 1)[1]

        headers = NoCaseDict()
        while True:
            line = cls._safe_readline(client_stream).strip().decode()
            if line == "":
                break
            header, value = line.split(":", 1)
            value = value.strip()
            headers[header] = value

        return cls(
            app, client_addr, method, url, http_version, headers, stream=client_stream
        )

    @classmethod
    def _safe_readline(cls, stream):
        line = stream.readline(cls.max_readline + 1)
        if len(line) > cls.max_readline:
            raise ValueError("line too long")
        return line

    def _parse_urlencoded(self, urlencoded):
        data = MultiDict()
        if len(urlencoded) > 0:
            for k, v in parse_qs(urlencoded).items():
                for x in v:
                    data[k] = x
        return data

    @property
    def body(self):
        """Request body as byte string"""
        if self._body is None:
            self._body = b""
            if self.content_length and self.content_length <= self.max_body_length:
                self._body = self._stream.read(self.content_length)
        return self._body

    @property
    def text(self):
        """Request body as text string"""
        return self.body.decode(self.charset)

    @property
    def json(self):
        """Parsed json from the request body"""
        if self._json is None:
            if self.content_type and self.content_type == "application/json":
                self._json = json.loads(self.body.decode(self.charset))
        return self._json

    @property
    def form(self):
        """Parsed form data from the request body"""
        if self._form is None:
            if (
                self.content_type
                and self.content_type == "application/x-www-form-urlencoded"
            ):
                self._form = self._parse_urlencoded(self.body.decode(self.charset))
        return self._form

    def after_request(self, f: Callable):
        self.after_request_handlers.append(f)
        return f


#####
# Response
#####


class Response:
    """Response object"""

    types_map = {
        "css": "text/css",
        "gif": "image/gif",
        "html": "text/html",
        "jpg": "image/jpeg",
        "js": "application/javascript",
        "json": "application/json",
        "png": "image/png",
        "txt": "text/plain",
    }
    send_file_buffer_size = 1024
    default_content_type = "text/plain"

    def __init__(
        self,
        body: Any = "",
        status_code: int = 200,
        headers: dict | None = None,
        reason: str | None = None,
        content_type: str | None = None,
        charset: str | None = None,
    ):
        if body is None and status_code == 200:
            body = b""
            status_code = 204

        self.status_code = status_code
        self.headers = headers or {}
        self.reason = reason or status.get(status_code).phrase
        self.content_type = content_type or self.default_content_type
        self.charset = charset or "utf-8"

        if isinstance(body, (dict, list)):
            self.body = json.dumps(body).encode(self.charset)
            self.content_type = "application/json"
        elif isinstance(body, str):
            self.body = body.encode(self.charset)
        else:
            self.body = body

    def __repr__(self):
        return f"<Response: {self.content_type} >"

    def set_cookie(
        self,
        cookie: str,
        value: str,
        path: str = "/",
        domain: str = None,
        expires: str | datetime = None,
        max_age: int | None = None,
        secure: bool = False,
        http_only: bool = False,
    ):
        """Set a cookie on the response"""
        http_cookie = "{}={}".format(cookie, value)
        if path:
            http_cookie += "; Path={}".format(path)
        if domain:
            http_cookie += "; Domain={}".format(domain)
        if expires:
            if isinstance(expires, str):
                http_cookie += "; Expires={}".format(expires)
            else:
                http_cookie += "; Expires={%a, %d %b %Y %H:%M:%S GMT}".format(expires)
        if max_age:
            http_cookie += "; Max-Age={}".format(max_age)
        if secure:
            http_cookie += "; Secure"
        if http_only:
            http_cookie += "; HttpOnly"
        self.headers.setdefault("Set-Cookie", []).append(http_cookie)

    def complete(self):
        """Complete the response"""
        if isinstance(self.body, bytes) and "Content-Length" not in self.headers:
            self.headers["Content-Length"] = str(len(self.body))
        if "Content-Type" not in self.headers:
            self.headers["Content-Type"] = "{}; charset={}".format(
                self.content_type, self.charset
            )

    def write(self, stream):
        """Write or send the response"""
        self.complete()
        stream.write(
            "HTTP/1.0 {} {}\r\n".format(self.status_code, self.reason).encode(
                self.charset
            )
        )

        for header, value in self.headers.items():
            values = value if isinstance(value, list) else [value]
            for value in values:
                stream.write("{}: {}\r\n".format(header, value).encode(self.charset))
        stream.write(b"\r\n")

        can_flush = hasattr(stream, "flush")
        try:
            for body in self.body_iter():
                if isinstance(body, str):
                    body = body.encode(self.charset)
                stream.write(body)
                if can_flush:
                    stream.flush()
        except OSError as exc:
            if exc.errno not in [32, 54, 104, 128]:
                raise

    def body_iter(self):
        """Body content as iterator"""
        if self.body:
            if hasattr(self.body, "read"):
                while True:
                    buf = self.body.read(self.send_file_buffer_size)
                    if len(buf):
                        yield buf
                    if len(buf) < self.send_file_buffer_size:
                        break
                if hasattr(self.body, "close"):
                    self.body.close()
            elif hasattr(self.body, "__next__"):
                yield from self.body
            else:
                yield self.body

    @classmethod
    def redirect(cls, location, status_code=302):
        """Redirect to another URL"""
        if "\x0d" in location or "\x0a" in location:
            raise ValueError("invalid redirect URL")
        return cls(status_code=status_code, headers={"Location": location})

    @classmethod
    def send_file(
        cls,
        filename: str | Path,
        status_code: int = 200,
        content_type: str | None = None,
        headers: dict | None = None,
    ):
        """Send a file as response"""
        p = Path(filename)
        headers = headers or {}

        if not p.is_file():
            return cls(status_code=404)

        if content_type is None:
            content_type = headers.get("Content_type")
        if content_type is None:
            ext = p.suffix
            if ext in Response.types_map:
                content_type = Response.types_map[ext]
            else:
                content_type = "application/octet-stream"
        headers["Content-Type"] = content_type

        f = p.open("rb")
        return cls(body=f, status_code=status_code, headers=headers)


class HTMLResponse(Response):
    default_content_type = "text/html"


#####
# Server
#####


class URLPattern:
    """URL pattern"""

    def __init__(self, url_pattern: str):
        self.url_pattern = url_pattern
        self.pattern = ""
        self.args = []
        self.parts = []

        use_regex = False
        pattern = ["/"]
        for segment in url_pattern.lstrip("/").split("/"):
            if not segment:
                continue
            self.parts.append(segment)
            if segment[0] == "<":
                if segment[-1] != ">":
                    raise ValueError("invalid URL pattern")
                segment = segment[1:-1]
                if ":" in segment:
                    tp, nm = segment.rsplit(":", 1)
                else:
                    tp = "string"
                    nm = segment
                if tp == "string":
                    pattern.append("/([^/]+)")
                elif tp == "int":
                    pattern.append("/(\\d+)")
                elif tp == "path":
                    pattern.append("/(.+)")
                elif tp.startswith("re:"):
                    pattern.append("/({})".format(tp[3:]))
                else:
                    raise ValueError("invalid URL segment type")
                use_regex = True
                self.args.append((tp, nm))
            else:
                pattern.append("/{}".format(segment))

        if len(pattern) > 1:
            pattern.pop(0)
        pattern = "".join(pattern)

        if use_regex:
            self.pattern = re.compile("^{}$".format(pattern))
        else:
            self.pattern = pattern

    def __repr__(self):
        return f"<URLPattern: {self.url_pattern}>"

    def get_url(self, args):
        url = []
        for p in self.parts:
            if p.startswith("<"):
                if ":" in p:
                    p = p.split(":", 1)[1]
                url.append(args[p])
            else:
                url.append(p)
        return "/" + "/".join(url)

    def match(self, path):
        """Does a request path match this pattern? Returns the values of any path parameters"""
        if isinstance(self.pattern, str):
            if path != self.pattern:
                return None
            return {}

        g = self.pattern.match(path)
        if not g:
            return None

        args = {}
        for i, arg in enumerate(self.args, start=1):
            value = g.group(i)
            if arg[0] == "int":
                value = int(value)
            args[arg[1]] = value
        return args


class SubServer:
    """Los Hoes subserver"""

    def __init__(self):
        self.url_map = []
        self.before_request_handlers = []
        self.after_request_handlers = []
        self.after_error_request_handlers = []
        self.error_handlers = {}

    def route(self, url_pattern: str, methods: Iterable | None = None, name: str = None):
        """Decorator: bind a function to an URL pattern for the given http methods

        The function takes a request object and any arguments present in the URL pattern.
        """
        pattern = URLPattern(url_pattern)
        if methods is None:
            methods = ["GET"]
        else:
            methods = list(methods)

        def decorated(f: Callable):
            self.url_map.append((methods, pattern, f, name))
            return f

        return decorated

    def url_for(self, name: str, **kwargs):
        """Find named url"""
        for _, pattern, _, url_name in self.url_map:
            if url_name == name:
                return pattern.get_url(kwargs)
        raise KeyError("No url by that name")

    def get(self, url_pattern: str, name: str = None):
        """Decorator: bind a function to an URL pattern for the GET method"""
        return self.route(url_pattern, ["GET"], name)

    def post(self, url_pattern: str, name: str = None):
        """Decorator: bind a function to an URL pattern for the POST method"""
        return self.route(url_pattern, ["POST"], name)

    def put(self, url_pattern: str, name: str = None):
        """Decorator: bind a function to an URL pattern for the PUT method"""
        return self.route(url_pattern, ["PUT"], name)

    def patch(self, url_pattern: str, name: str = None):
        """Decorator: bind a function to an URL pattern for the PATCH method"""
        return self.route(url_pattern, ["PATCH"], name)

    def delete(self, url_pattern: str, name: str = None):
        """Decorator: bind a function to an URL pattern for the DELETE method"""
        return self.route(url_pattern, ["DELETE"], name)

    def head(self, url_pattern: str, name: str = None):
        """Decorator: bind a function to an URL pattern for the HEAD method"""
        return self.route(url_pattern, ["HEAD"], name)

    def before_request(self, f: Callable[[Request], Any]):
        """Run a function before any request is handled

        The function takes a request object.
        If this function has a result, it is sent instead of a regular response.
        """
        self.before_request_handlers.append(f)
        return f

    def after_request(self, f: Callable[[Request, Response], Any]):
        """Run a function after any request is successfully handled

        The function takes a request and a response object.
        If this function has a result, it is sent instead of a regular response.
        """
        self.after_request_handlers.append(f)
        return f

    def after_error_request(self, f: Callable[[Request, Response], Any]):
        """Run a function after any request fails

        The function takes a request and a response object.
        If this function has a result, it is sent instead of a regular response.
        """
        self.after_error_request_handlers.append(f)
        return f

    def error_handler(self, code_or_exception: int | Type[Exception]):
        """Run a function when any request fails

        The function takes a request object and either an error code or an exception.
        If this function has a result, it is sent instead of a regular response.
        """

        def decorated(f: Callable[[int | Type[Exception]], Any]):
            self.error_handlers[code_or_exception] = f
            return f

        return decorated

    def mount(self, subapp: Self, url_prefix: str = ""):
        """Embed another app inside this one with an optional URL prefix"""
        for methods, pattern, handler, name in subapp.url_map:
            self.url_map.append(
                (methods, URLPattern(url_prefix + pattern.url_pattern), handler, name)
            )
        for handler in subapp.before_request_handlers:
            self.before_request_handlers.append(handler)
        for handler in subapp.after_request_handlers:
            self.after_request_handlers.append(handler)
        for handler in subapp.after_error_request_handlers:
            self.after_error_request_handlers.append(handler)
        for code_or_exception, handler in subapp.error_handlers.items():
            self.error_handlers[code_or_exception] = handler


class Server(SubServer):
    """Los Hoes mini server"""

    def __init__(self):
        super().__init__()
        self.shutdown_requested = False
        self.debug = False
        self.server = None

    def find_route(self, req: Request):
        """Find which handler to use for a request"""
        f = 404
        for methods, pattern, handler, _ in self.url_map:
            req.url_args = pattern.match(req.path)
            if req.url_args is not None:
                if req.method in methods:
                    f = handler
                    break
                else:
                    f = 405
        return f

    @staticmethod
    def server_info(host: str | None, port: int) -> tuple:
        """Get server information: protocol family and address"""
        ai = socket.getaddrinfo(host, port, flags=socket.AI_PASSIVE)
        return ai[0][0], ai[0][-1]

    @staticmethod
    def abort(status_code: int, reason: str | None = None):
        """Abort the current action (raise an HTTPException)"""
        raise HTTPException(status_code, reason)

    def shutdown(self):
        """Set the app to shutdown after this request"""
        self.shutdown_requested = True

    def run(
        self,
        host: str | None = "127.0.0.1",
        port: int = 5001,
        use_threading: bool = True,
        cert_file: str = None,
        key_file: str = None,
    ):
        """Start the server"""
        self.shutdown_requested = False
        self.use_threading = use_threading

        fam, addr = self.server_info(host, port)
        self.address = addr

        if socket.has_dualstack_ipv6 and fam == socket.AF_INET6:
            self.server = socket.create_server(addr, family=fam, dualstack_ipv6=True)
        else:
            self.server = socket.create_server(addr, family=fam)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.settimeout(10)

        if cert_file:
            ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ssl_context.load_cert_chain(cert_file, key_file)
            self.server = ssl_context.wrap_socket(self.server, server_side=True)

        try:
            while not self.shutdown_requested:
                try:
                    sock, addr = self.server.accept()
                except socket.timeout:
                    pass
                except OSError as exc:
                    if exc.errno in (errno.ECONNABORTED, errno.ENOTSOCK):
                        break
                    else:
                        print_exception(exc)
                except Exception as exc:
                    print_exception(exc)
                else:
                    if self.use_threading:
                        import threading

                        threading.Thread(
                            target=self.handle_request, args=(sock, addr)
                        ).start()
                    else:
                        self.handle_request(sock, addr)
        except KeyboardInterrupt:
            pass

    def handle_request(self, sock: socket.SocketType, addr: tuple):
        """Handle a single request"""
        if Request.socket_read_timeout:
            sock.settimeout(Request.socket_read_timeout)
        stream = sock.makefile("rwb")

        req = None
        resp = None
        # request
        try:
            req = Request.create(self, stream, addr)
            resp = self.dispatch_request(req)
        except socket.timeout as exc:
            if exc.errno and exc.errno not in [60, 110]:  # not actually timeouts
                print_exception(exc)
        except Exception as exc:
            print_exception(exc)

        # response
        try:
            if hasattr(resp, "write"):
                resp.write(stream)
            stream.close()
        except OSError as exc:
            if exc.errno in [32, 54, 104, 128]:  # harmless
                pass
            else:
                print_exception(exc)
        except Exception as exc:
            print_exception(exc)

        if stream != sock:
            sock.close()
        if self.shutdown_requested:
            self.server.close()

    def dispatch_request(self, req) -> Response:
        """Determine the response of a request"""
        # problem with request
        if not req:
            return self.make_response(req, error=400)
        if req.content_length > req.max_content_length:
            return self.make_response(req, error=413)

        f = self.find_route(req)
        try:
            # problem finding handler
            if isinstance(f, int):
                return self.make_response(req, error=f)
            if callable(f):
                # normal response
                resp = None
                for handler in self.before_request_handlers:
                    resp = handler(req)
                    if resp:
                        break
                if resp is None:
                    resp = f(req, **req.url_args)
                return self.make_response(req, resp)
        # problem with response
        except HTTPException as exc:
            return self.make_response(req, exc.reason, error=exc.status_code)
        except Exception as exc:
            print_exception(exc)
            error = 500
            if exc.__class__ in self.error_handlers:
                error = exc.__class__
            return self.make_response(req, error=error)

        # problem with anything else
        return self.make_response(req, error=500)

    def make_response(
        self, req: Request, resp: Any = None, error: int | Type[Exception] | None = None
    ) -> Response:
        """Make a response"""
        if error:
            if error in self.error_handlers:
                try:
                    resp = self.error_handlers[error](req, error)
                except Exception as exc:
                    print_exception(exc)
                    resp = Response(resp, status_code=error)
            else:
                resp = Response(resp, status_code=error)
        elif isinstance(resp, tuple):
            resp = Response(*resp)
        elif not isinstance(resp, Response):
            resp = Response(resp)

        after_request_handlers = (
            self.after_request_handlers + req.after_request_handlers
        )
        if error:
            after_request_handlers = self.after_error_request_handlers
        for handler in after_request_handlers:
            resp = handler(req, resp) or resp

        return resp


class Static:
    """For serving static pages from one or more directories

    Use as:
    app.get("/static/<path:path>")(Static(dir1, dir2, ...))
    """

    def __init__(self, *paths: str | Path):
        self.paths = [Path(p) for p in paths]

    def __call__(self, req: Request, path: str):
        if ".." in path:
            return Response(status_code=404)
        for p in self.paths:
            if (p / path).is_file():
                return Response.send_file(p / path)
        return Response(status_code=404)


#####
# Main application
#####

app = Server()
