#!/usr/bin/env python3
# encoding: UTF-8

"""Post discord messages from a config file.
"""

__author__ = "Rogier Steehouder"
__date__ = "2022-10-18"
__version__ = "0.1"

import sys
import pathlib

import click
import httpx
from loguru import logger

try:
    import tomllib  # type: ignore
except:
    import tomli as tomllib  # type: ignore

# Click documentation: https://click.palletsprojects.com/
@click.command()
@click.option("-c", "--channel", default="", help="""Discord channel defined in config""")
@click.option("-m", "--message", default="", help="""Message defined in config""")
@click.option("-r", "--role", default="", help="""Mention role defined in config""")
@click.option("-p", "--preset", default="", help="""Preset defined in config""")
@click.option(
    "--loglevel",
    default="warning",
    type=click.Choice(
        ["trace", "debug", "info", "success", "warning", "error", "critical"],
        case_sensitive=False,
    ),
)
def main(loglevel, channel, message, role, preset):
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

        logger.info("Start")

        cfg = tomllib.loads(pathlib.Path(__file__).with_suffix(".toml").read_text())

        p = cfg.get("presets", {}).get(preset)
        if p:
            channel = p["channel"]
            message = p["message"]
            role = p.get("role", "")

        with httpx.Client() as cli:
            chan = cfg["channels"][channel]
            msg = cfg["messages"][message]
            rl = cfg["mentions"].get(role, "")
            if rl:
                msg = f"{rl} {msg}"

            logger.debug("Webhook: {}", chan)
            logger.debug("Message: {}", msg)

            resp = cli.post(chan, params={"wait": True}, json={"content": msg})
            logger.info("Message id: {}", resp.json()["id"])

        logger.success("Complete")

        return 0


if __name__ == "__main__":
    main()
