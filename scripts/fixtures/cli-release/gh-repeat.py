#!/usr/bin/env python3
"""Read-only GitHub simulator for executing the actual publish reconciliation.

Every attempted mutation is recorded and refused, so a repeat/conflict test
cannot accidentally contact GitHub or hide a write in a mocked response.
"""
import json
import os
import pathlib
import sys

state = json.loads(pathlib.Path(os.environ["CLI_REPEAT_STATE"]).read_text())
args = sys.argv[1:]
with pathlib.Path(os.environ["CLI_REPEAT_LOG"]).open("a") as log:
    log.write(json.dumps(args) + "\n")
if args[0] != "api" or "--method" in args or "release" in args:
    raise SystemExit(88)
route = next(arg for arg in args if arg.startswith("repos/"))
if route.endswith("/git/ref/tags/" + state["tag"]):
    value = {"object": {"type": state.get("tagType", "tag"), "sha": "a" * 40}}
elif "/git/tags/" in route:
    value = state["source"] if "--jq" in args else {"object": {"sha": state["source"]}}
elif route.endswith("/releases?per_page=100"):
    if state.get("discoveryError"):
        raise SystemExit(1)
    value = [[state["release"]]]
elif route.endswith("/releases/1/assets?per_page=100"):
    value = [state["assets"]]
elif "/releases/assets/" in route:
    asset_id = int(route.rsplit("/", 1)[1])
    asset = next(item for item in state["assets"] if item["id"] == asset_id)
    content = (pathlib.Path(state["directory"]) / asset["name"]).read_bytes()
    if state.get("tamper") == asset["name"]:
        content = bytes([content[0] ^ 1]) + content[1:]
    sys.stdout.buffer.write(content)
    raise SystemExit(0)
else:
    raise SystemExit(89)
print(value if isinstance(value, str) else json.dumps(value))
