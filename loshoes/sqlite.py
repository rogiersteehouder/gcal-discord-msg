import sqlite3
from pathlib import Path

from typing import Callable

from .auth import BaseUserCheck


class DBUserCheck(BaseUserCheck):
    def __init__(self, connect: Callable):
        self.connect = connect

    def has_userid(self, userid: str) -> bool:
        result = False
        with self.connect() as conn:
            for row in conn.execute(
                """select 1 from accounts where userid = ?""", (userid,)
            ):
                result = True
        return result

    def get_hash(self, userid: str) -> str:
        result = ""
        with self.connect() as conn:
            for row in conn.execute(
                """select hash from accounts where userid = ?""", (userid,)
            ):
                result = row[0]
        return result


class Database:
    def __init__(self, db_file: Path | str):
        self.db_file = Path(db_file)
        if not self.db_file.exists():
            self.init_db()

        self.user_check = DBUserCheck(self.connect)

    def connect(self):
        return sqlite3.connect(self.db_file)

    def init_db(self):
        with self.connect() as conn:
            conn.executescript(
                """
                begin;
                create table accounts ("userid" text primary key not null, "hash" text not null);
                create table key_value ("domain" text not null, "key" text not null, "value" text not null, primary key ("domain", "key"));
                commit;
            """
            )

    def get(self, domain: str, key: str, default: str | None = None):
        result = None
        with self.connect() as conn:
            for row in conn.execute(
                """select value from key_value where domain = ? and key = ?""", (domain, key)
            ):
                result = row[0]
        return result

    def set(self, domain: str, key: str, value: str):
        with self.connect() as conn:
            conn.execute("""insert or replace into key_value values (?, ?, ?)""", (domain, key, value))
