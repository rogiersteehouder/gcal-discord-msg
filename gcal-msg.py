#!/usr/bin/env python3
# encoding: UTF-8

"""Google calendar to discord messages

It's looking for events in the future in a perticular calendar (see config file)
with an entry in the description like:

{
    "discord-msg": {
        "label": "optional comment above crontab entry",
        "channel": "channel as defined in discord-msg config",
        "message": "message as defined in discord-msg config",
        "mention": "optional mention as defined in discord-msg config",
        "preset": "preset as defined in sicord-msg config (replaces channel, message and mention)",
        "offset": <number of seconds before the event to send the message>
    }
}
"""

__author__ = "Rogier Steehouder"
__date__ = "2022-10-21"
__version__ = "0.1"

import sys
import datetime
import pathlib
import re
import json
import html
from typing import List

import click
import httpx
from loguru import logger

try:
    import tomllib  # type: ignore
except:
    import tomli as tomllib  # type: ignore


class Default(dict):
    def __missing__(self, key):
        return "-"


class APIError(Exception):
    def __str__(self):
        return "{} - {}".format(*self.args[0:2])


def get_auth(
    http_client: httpx.Client, client_id: str, client_secret: str, refresh_token: str
):
    token = http_client.post(
        "https://oauth2.googleapis.com/token",
        data={
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
        },
    ).json()
    if "error" in token:
        raise APIError(token["error"], token.get("error_description", ""))
    if "access_token" not in token:
        raise APIError("unknown", "Response has no access_token")
    return (token.get("token_type", "Bearer"), token["access_token"])


def get_events(http_client: httpx.Client, calendar_id: str, utcnow: datetime.datetime):
    events = http_client.get(
        "https://www.googleapis.com/calendar/v3/calendars/{}/events".format(
            calendar_id
        ),
        params={
            "orderBy": "startTime",
            "singleEvents": True,
            "timeMin": utcnow.isoformat(),
        },
    ).json()
    if "error" in events:
        raise APIError(events["error"], events.get("error_description", ""))
    return events["items"]


def edit_crontab(crontab: pathlib.Path, cronlines: List[str]):
    start = "#### START discord-msg"
    end = "#### END discord-msg"
    ct = crontab.read_text().split("\n")
    if ct[-1] == "":
        del ct[-1]
    # remove old entries
    i = 0
    remove = False
    while i < len(ct):
        if ct[i].startswith(start):
            remove = True
        if remove:
            if ct[i].startswith(end):
                remove = False
            del ct[i]
        else:
            i += 1
    # add new entries
    ct += [start]
    ct += cronlines
    ct += [end, ""]
    crontab.write_text("\n".join(ct))


# Click documentation: https://click.palletsprojects.com/
@click.command()
@click.option(
    "--crontab",
    type=click.Path(exists=True, dir_okay=False, path_type=pathlib.Path),
    help="""Update crontab (use as editor for `crontab -e`)""",
)
@click.option(
    "--loglevel",
    default="warning",
    type=click.Choice(
        ["trace", "debug", "info", "success", "warning", "error", "critical"],
        case_sensitive=False,
    ),
)
def main(loglevel: str, crontab: pathlib.Path):
    logger.remove()
    logger.add(
        sys.stderr,
        format="<light-black>{time:YYYY-MM-DD HH:mm:ss}</light-black> | <level>{level: <8}</level> | {message}",
        level=loglevel.upper(),
    )
    logger.add(
        pathlib.Path(__file__).with_suffix(".log"),
        format="<light-black>{time:YYYY-MM-DD HH:mm:ss}</light-black> | <level>{level: <8}</level> | {message}",
        level="DEBUG",
        rotation="1 week",
        retention=5,
    )
    with logger.catch(onerror=lambda _: sys.exit(1)):

        cfg = tomllib.loads(pathlib.Path(__file__).with_suffix(".toml").read_text())
        utcnow = datetime.datetime.now(tz=datetime.timezone.utc)

        logger.info("Start")

        with httpx.Client() as cli:

            try:

                # Auth token
                logger.debug("New auth token")
                cli.headers.update(
                    {
                        "Authorization": "{} {}".format(
                            *get_auth(
                                cli,
                                cfg["client_id"],
                                cfg["client_secret"],
                                cfg["refresh_token"],
                            )
                        )
                    }
                )

                # GCal events
                logger.debug("Get calendar events")
                events = get_events(cli, cfg["calendar_id"], utcnow)

            except APIError as err:
                logger.error("Google API error: {}", err)
                return 1

            striptags = re.compile("<.*?>")
            cronlines = []

            for event in events:
                if "discord-msg" in event.get("description", ""):
                    logger.debug("Event: {}", event["summary"])
                    dttm = datetime.datetime.fromisoformat(
                        event["start"]["dateTime"].replace("Z", "+00:00")
                    )
                    data = json.loads(
                        html.unescape(striptags.sub("", event["description"])).replace(
                            "\xa0", " "
                        ),
                        object_hook=Default,
                    )["discord-msg"]
                    dttm -= datetime.timedelta(seconds=data["offset"])
                    data["dttm"] = dttm

                    if "label" in data:
                        cronlines.append("# {label}".format_map(data))
                    if "preset" in data:
                        cronlines.append(
                            "{dttm:%M\t%H\t%d\t%m\t*}\tpython3 ${{HOME}}/msg/discord-msg.py -p {preset}".format_map(
                                data
                            )
                        )
                    else:
                        cronlines.append(
                            "{dttm:%M\t%H\t%d\t%m\t*}\tpython3 ${{HOME}}/msg/discord-msg.py -c {channel} -m {message} -r {mention}".format_map(
                                data
                            )
                        )

            # IMPORTANT: use this script as editor for crontab:
            # > EDITOR='python gcal-msg.py --crontab' crontab -e
            if crontab:
                logger.debug("Edit crontab")
                edit_crontab(crontab, cronlines)
            else:
                logger.debug("Output crontab lines")
                print("\n".join(cronlines))

        logger.success("Complete")
    return 0


if __name__ == "__main__":
    # pylint: disable=all
    main()
