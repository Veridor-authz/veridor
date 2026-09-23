"""Start datasette in the configuration CVE-2023-40570 is about.

The instance is private: metadata allows view-instance to the actor "owner"
and to no one else, and nothing inside it is opened up again, so an anonymous
caller should be refused everywhere but the static assets. The API explorer at
/-/api did not check view-instance before 1.0a4, which is the bug. Nothing is
allowed below the instance: `allow: true` on the database makes its page
public on both releases (measured), which is not the configuration the
advisory describes.

Runs at container start because datasette reads its metadata once, at startup.
The signing secret comes from DATASETTE_SECRET, which the harness sets and
which `datasette create-token` reads as well.
"""
import json
import os
import sqlite3

DATA = "/data"

connection = sqlite3.connect(f"{DATA}/private.db")
connection.execute("CREATE TABLE IF NOT EXISTS secrets (id INTEGER PRIMARY KEY, note TEXT)")
connection.execute("INSERT INTO secrets (note) VALUES ('owner only')")
connection.commit()
connection.close()

metadata = {"allow": {"id": "owner"}}
with open(f"{DATA}/metadata.json", "w", encoding="utf-8") as handle:
    json.dump(metadata, handle)

os.execvp("datasette", [
    "datasette", "serve", "--host", "0.0.0.0", "--port", "8001",
    "--metadata", f"{DATA}/metadata.json", f"{DATA}/private.db",
])
