#!/usr/bin/env python3
# encoding: UTF-8

"""Send discord messages
"""

__author__ = "Rogier Steehouder"
__date__ = "2023-03-18"
__version__ = "1.0"

import datetime
import html
import json
import re
import sqlite3
import subprocess
from pathlib import Path
from typing import List

# Raspberry Pi: tomllib is new in python 3.11
try:
    import tomllib
except ImportError:
    import tomli as tomllib

import httpx
from jinja2 import FileSystemLoader

from loshoes.server import app, Request, Response, HTTPException
from loshoes.jinja import (
    jinja_environment,
    TemplateResponse,
    StringTemplateResponse,
    Navmenu,
)
from loshoes.sqlite import Database
from loshoes.auth_browser import login_auth

# from icecream import ic
# ic.configureOutput(prefix="DEBUG | ", includeContext=True)


cfg = tomllib.loads(Path(__file__).with_suffix(".toml").read_text())
db = Database(cfg["database"])
login_auth.except_hosts.append("127.0.0.1")
login_auth.user_check = db.user_check
jinja_environment.loader.loaders.append(FileSystemLoader(cfg["templates"]))
jinja_environment.globals["navmenu"] = Navmenu(
    [
        {"title": "Overview", "url": "/"},
        {"title": "Update", "url": "/update"},
        {"title": "Log out", "url": "/logout"},
    ]
)


#####
# Crontab
#####


class Crontab:
    def __init__(self):
        self.startline = "#### START discord-msg"
        self.endline = "#### END discord-msg"

        self.tab_pre = None
        self.tab_msg = None
        self.tab_post = None
        self.last_read = datetime.datetime.min
        self.timeout = datetime.timedelta(seconds=120)

        self.last_result = None

    def get(self):
        now = datetime.datetime.now()
        if now > self.last_read + self.timeout:
            self.tab = None
        if self.tab is None:
            tab = subprocess.run(
                ["crontab", "-l"],
                capture_output=True,
                timeout=5,
                text=True,
                check=True,
            ).stdout.splitlines()

            if self.startline in tab:
                s = tab.index(self.startline)
            else:
                s = len(tab)
            self.tab_pre = tab[:s] + [self.startline]

            if self.endline in tab:
                e = tab.index(self.endline)
            else:
                e = len(tab)
            self.tab_post = tab[e + 1 :] + [self.endline]

            self.tab_msg = tab[s + 1 : e]

            self.last_read = now

        return self.tab_pre + self.tab_msg + self.tab_post

    def set(self, tab_msg: List[str] = None):
        if self.tab_pre is None:
            self.get()
        if tab_msg is not None:
            self.tab_msg = tab_msg

        result = subprocess.run(
            ["crontab", "-"],
            input="\n".join(self.tab_pre + self.tab_msg + self.tab_post),
            capture_output=True,
            timeout=30,
            text=True,
            check=True,
        )
        self.last_result = result.stdout


#####
# Crontab updater
#####


class Default(dict):
    def __missing__(self, key):
        return "-"


class GCalUpdater:
    def __init__(self):
        self.headers = {}
        self.log = []

    def get_auth(self):
        client_id = db.get("gcal", "client_id")
        client_secret = db.get("gcal", "client_secret")
        refresh_token = db.get("gcal", "refresh_token")
        try:
            resp = httpx.post(
                "https://oauth2.googleapis.com/token",
                data={
                    "client_id": client_id,
                    "client_secret": client_secret,
                    "grant_type": "refresh_token",
                    "refresh_token": refresh_token,
                },
            )
            token = resp.json()
        except:
            if resp:
                raise HTTPException(resp.status_code, resp.text)
            else:
                raise
        if "error" in token:
            raise HTTPException(token["error"], token.get("error_description", ""))
        if "access_token" not in token:
            raise HTTPException(500, "Response has no access_token")
        self.headers["Authorization"] = "{} {}".format(
            token.get("token_type", "Bearer"), token["access_token"]
        )

    def get_events(self):
        calendar_id = db.get("gcal", "calendar_id")
        try:
            resp = httpx.get(
                f"https://www.googleapis.com/calendar/v3/calendars/{calendar_id}/events",
                headers=self.headers,
                params={
                    "orderBy": "startTime",
                    "singleEvents": True,
                    "timeMin": datetime.datetime.now(
                        tz=datetime.timezone.utc
                    ).isoformat(),
                },
            )
            events = resp.json()
        except:
            if resp:
                raise HTTPException(resp.status_code, resp.text)
            else:
                raise
        if "error" in events:
            raise HTTPException(events["error"]["code"], events["error"].get("message", ""))
        return events["items"]

    def update(self):
        self.get_auth()
        events = self.get_events()

        striptags = re.compile("<.*?>")

        with db.connect() as conn:
            conn.execute("""delete from crontab""")
            for seqno, event in enumerate(events):
                if "discord-msg" in event.get("description", ""):
                    dttm = datetime.datetime.fromisoformat(
                        event["start"]["dateTime"].replace("Z", "+00:00")
                    )
                    self.log.append(
                        "Event {}: {:%Y-%m-%d %H:%M} {}".format(
                            seqno, dttm, event["summary"]
                        )
                    )
                    data = json.loads(
                        html.unescape(striptags.sub("", event["description"])).replace(
                            "\xa0", " "
                        ),
                        object_hook=Default,
                    )["discord-msg"]

                    dttm -= datetime.timedelta(seconds=data["offset"])
                    conn.execute(
                        """insert into crontab values (?, ?, ?, ?)""",
                        (
                            seqno,
                            data.get("label", ""),
                            f"{dttm:%M\t%H\t%d\t%m\t*}",
                            data["preset"],
                        ),
                    )

        self.log.append("Installing as crontab:")
        cronlines = []
        with db.connect() as conn:
            for row in conn.execute("""select * from crontab order by seqno asc"""):
                if row[1]:
                    for line in row[1].splitlines():
                        cronlines.append(f"# {line}")
                cronlines.append(
                    f'{row[2]}\tcurl "http://127.0.0.1:{app.address[1]}/ws/send?preset={row[3]}"'
                )

        ct = Crontab()
        ct.set(cronlines)
        self.log.append(ct.last_result)

        return self.log


#####
# Webservices
#####


@app.get("/ws/crontab", "crontab")
def get_crontab(req: Request = None):
    """Get the current installed crontab"""
    try:
        return Crontab().get()
    except subprocess.CalledProcessError as exc:
        return Response(exc.stderr, status_code=500)


@app.get("/ws/update", "update")
def gcal_update(req: Request):
    """Update the crontab from the calendar"""
    return GCalUpdater().update()


@app.get("/ws/send", "send")
def send_preset(req: Request):
    """Send a discord message"""
    preset = req.args.get("preset")
    if not preset:
        return Response(
            {"error": 400, "description": "Missing argument: preset"}, status_code=400
        )
    with db.connect() as conn:
        channel, mention, message = conn.execute(
            """select c.url, m.code, p.message from presets p inner join channels c on c.channelid = p.channelid left outer join mentions m on m.mentionid = p.mentionid where p.presetid = ?""",
            (preset,),
        ).fetchone()
    if mention:
        message = f"{mention} {message}"
    resp = httpx.post(channel, params={"wait": True}, json={"content": message})
    resp.raise_for_status()
    return resp.json()


#####
# Google Access
#####


@app.get("/google", "google")
def google(req: Request):
    """Google access request page"""
    client_id = db.get("gcal", "client_id")
    if not client_id:
        raise HTTPException(500, "No Google client id")
    return StringTemplateResponse(
        """{% extends 'msg.html.j2' %}
{% block subtitle %}Google Consent{% endblock %}
{% block content %}
<p>We will need consent from you to use your Google account to access the calendar</p>
<form method="post" action="https://accounts.google.com/o/oauth2/auth">
<input type="hidden" name="client_id" value="{{client_id}}" />
<input type="hidden" name="redirect_uri" value="{{redirect_uri}}" />
<input type="hidden" name="response_type" value="code" />
<input type="hidden" name="scope" value="https://www.googleapis.com/auth/calendar.readonly" />
<p><button type="submit">Google Calendar Access</button></p>
</form>
{% endblock %}""",
        {
            "request": req,
            "client_id": client_id,
            "redirect_uri": "http://localhost:{}/google-response".format(
                req.app.address[1]
            ),
        },
    )


@app.get("/google-response")
def google_response(req: Request):
    """Google access response"""
    code = req.args.get("code")
    if not code:
        if req.args.get("error"):
            req.g.messages.append({"text": req.args.get("error"), "categories": ["error"]})
        else:
            req.g.messages.append({"text": "Unknown error", "categories": ["error"]})

        return StringTemplateResponse(
            """{% extends 'msg.html.j2' %}
{% block subtitle %}Google Consent{% endblock %}
{% block content %}
<p>No refresh token.</p>
{% endblock %}""",
            {"request": req},
        )

    data = {
        "client_id": db.get("gcal", "client_id"),
        "client_secret": db.get("gcal", "client_secret"),
        "code": code,
        "grant_type": "authorization_code",
        "redirect_uri": "http://localhost:{}/google-response".format(
            req.app.address[1]
        ),
    }
    resp = httpx.post("https://oauth2.googleapis.com/token", json=data)
    resp.raise_for_status()
    token = resp.json()
    db.set("gcal", "refresh_token", token["refresh_token"])

    return StringTemplateResponse(
        """{% extends 'msg.html.j2' %}
{% block subtitle %}Google Consent{% endblock %}
{% block content %}
<p>{{ message }}</p>
{% endblock %}""",
        {
            "request": req,
            "message": "Refresh token: {}".format(db.get("gcal", "refresh_token")),
        },
    )


#####
# Site Pages
#####


@app.route("/", ["GET", "POST"], "index")
def page_index(req: Request):
    if req.method == "POST":
        row = (
            req.form.get("presetid"),
            req.form.get("channelid"),
            req.form.get("mentionid"),
            req.form.get("message"),
        )
        try:
            with db.connect() as conn:
                conn.execute(
                    """insert or replace into presets values (?, ?, ?, ?)""", row
                )
        except sqlite3.IntegrityError:
            req.g.messages.append({"text": "Required value missing.", "categories": ["error"]})

    with db.connect() as conn:
        channels = list(
            conn.execute("""select channelid from channels order by channelid""")
        )
        mentions = list(
            conn.execute("""select mentionid from mentions order by mentionid""")
        )
        presets = list(
            conn.execute("""select * from presets order by channelid, presetid""")
        )
        crontab = list(conn.execute("""select * from crontab order by seqno"""))

    return TemplateResponse(
        "index.html.j2",
        {
            "request": req,
            "crontab": crontab,
            "presets": presets,
            "channels": channels,
            "mentions": mentions,
        },
    )


@app.get("/update")
def page_update(req: Request):
    token = db.get("gcal", "refresh_token")
    if not token:
        return Response.redirect(req.app.url_for("google"))

    return StringTemplateResponse(
        """{% extends 'msg.html.j2' %}
{% block head %}
<script>
function updateCrontab() {
	return fetch('{{ url_for("update") }}')
		.then(r => {
			if (!r.ok) { throw new Error(`Fetch went wrong: ${r.status} - ${r.statusText}`); }
			return r.json();
		})
		.then(l => { document.getElementById("update-output").textContent = l.join("\\n"); return true; })
		.catch(e => { console.log(e); return false; });
}
</script>
{% endblock %}
{% block subtitle %}Update{% endblock %}
{% block content %}
<dl class="form">
<dt>Update the crontab from the Google calendar</dt>
<dd><button onclick="updateCrontab()">Update Crontab</button></dd>
</dl>
<pre id="update-output" class="code"></pre>
{% endblock %}""",
        {"request": req},
    )


print("Msg: http://{host}:{port}/".format_map(cfg))
app.run(host=cfg["host"], port=cfg["port"])
