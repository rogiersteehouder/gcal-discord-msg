"""Use jinja2 templates with Los Hoes

The standard environment loads templates from the Los Hoes package templates directory.
To use them, you also need to serve the stylesheet:

    from loshoes.jinja import stylesheet
    @app.get(stylesheet.url)(stylesheet)

You can add additional template loaders by manipulating the jinja_environment.loader.loaders list:

    jinja_environment.loader.loaders.append(FileSystemLoader("templates"))

After this, you can use TemplateResponse and StringTemplateResponse.
"""

import importlib.resources
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import jinja2.ext
from jinja2 import Environment, ChoiceLoader, PackageLoader, select_autoescape
from jinja2.lexer import Token

from .server import app, Request, Response


#####
# Jinja Environment
#####

class NewlineRemover(jinja2.ext.Extension):
    """Remove empty lines from the start of generated html"""

    def filter_stream(self, stream):
        skip = True
        for token in stream:
            if skip and token.type == "data":
                t = token.value.lstrip()
                if not t:
                    continue
                skip = False
                if t.startswith("<!DOCTYPE"):
                    token = Token(token.lineno, token.type, t)
            yield token


jinja_environment = Environment(
    loader=ChoiceLoader([PackageLoader(__package__)]),
    autoescape=select_autoescape(),
    trim_blocks=True,
    lstrip_blocks=True,
    keep_trailing_newline=True,
    extensions=[jinja2.ext.loopcontrols, jinja2.ext.do, NewlineRemover],
)
jinja_environment.globals.update(
    {
        "datetime": datetime,
        "timezone": timezone,
        "Path": Path,
        "url_for": app.url_for,
    }
)


#####
# Template rendering
#####

def render_template(template: str, *args, **kwargs):
    """Render a template."""
    template = jinja_environment.get_template(template)
    return template.render(*args, **kwargs)


def render_string(template: str, *args, **kwargs):
    """Render a string template."""
    template = jinja_environment.from_string(template)
    return template.render(*args, **kwargs)


class TemplateResponse(Response):
    """Response from a Jinja2 template"""
    default_content_type = "text/html"

    def __init__(
        self,
        template: str,
        context: Optional[dict] = None,
        status_code: int = 200,
        headers: Optional[dict] = None,
        reason: Optional[str] = None,
        content_type: Optional[str] = None,
        charset: Optional[str] = None,
    ):
        super().__init__(
            render_template(template, context or {}),
            status_code,
            headers,
            reason,
            content_type,
            charset,
        )


class StringTemplateResponse(Response):
    """Response from a Jinja2 string template"""
    default_content_type = "text/html"

    def __init__(
        self,
        template: str,
        context: Optional[dict] = None,
        status_code: int = 200,
        headers: Optional[dict] = None,
        reason: Optional[str] = None,
        content_type: Optional[str] = None,
        charset: Optional[str] = None,
    ):
        super().__init__(
            render_string(template, context or {}),
            status_code,
            headers,
            reason,
            content_type,
            charset,
        )


#####
# Default stylesheet
#####

@app.get("/base.css")
def stylesheet(req):
    # python < 3.9 has older importlib.resources
    if hasattr(importlib.resources, "as_file"):
        with importlib.resources.as_file(importlib.resources.files(__package__).joinpath("static/base.css")) as f:
            return Response.send_file(f, content_type="text/css; charset=utf-8", headers={"Cache-Control": "max-age: 82800"})
    else:
        return Response.send_file(Path(__file__).parent / "static/base.css", content_type="text/css; charset=utf-8", headers={"Cache-Control": "max-age: 82800"})


#####
# Navigation
#####


class Navmenu:
    def __init__(self, menu):
        self.menu = menu

    def has_url(self, url, menu):
        for item in menu:
            if item.get("url") == url:
                return True
            if "items" in item:
                return self.has_url(url, item["items"])
        return False

    def navmenu(self, menu, html_class, sub_prefix, current_url):
        out = []
        if html_class:
            out.append(f'<ul class="{html_class}">')
        else:
            out.append("<ul>")

        for n, item in enumerate(menu):
            if "url" in item:
                if item["url"] == current_url:
                    out.append(
                        '<li class="current"><a href="{url}">{title}</a></li>'.format(
                            **item
                        )
                    )
                else:
                    out.append('<li><a href="{url}">{title}</a></li>'.format(**item))
            if "items" in item:
                checked = " checked" if self.has_url(item["items"]) else ""
                out.append(
                    f'<li><input type="checkbox" id="menu{sub_prefix}{n}" aria-label="submenu"{checked} /><label for="menu{sub_prefix}{n}">{item["title"]}</label>'
                )
                out.extend(
                    self.navmenu(item["items"], "", f"{sub_prefix}{n}-", current_url)
                )
                out.append("</li>")

        out.append("</ul>")
        return out

    def __call__(self, req: Request):
        current_url = req.path
        if current_url != "/":
            current_url = current_url.rstrip("/")
        return "\n".join(self.navmenu(self.menu, "menu", "-", current_url))
