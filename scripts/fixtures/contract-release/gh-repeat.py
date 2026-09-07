#!/usr/bin/env python3
"""Offline GitHub simulator for executing actual contract reconciliation.

Every command is recorded. Mutations are refused except explicitly enabled
fixture create/upload/publish operations, which update only the local state.
There is no network implementation or delegation to the real GitHub CLI.
"""
import json
import os
import pathlib
import sys

state = json.loads(pathlib.Path(os.environ["CONTRACT_REPEAT_STATE"]).read_text())
args = sys.argv[1:]
with pathlib.Path(os.environ["CONTRACT_REPEAT_LOG"]).open("a") as log:
    log.write(json.dumps(args) + "\n")
def save():
    pathlib.Path(os.environ["CONTRACT_REPEAT_STATE"]).write_text(json.dumps(state))

if args[:2] == ["release", "upload"]:
    if not state.get("allowMutations") or args[2] != state["tag"] or "--clobber" in args:
        raise SystemExit(88)
    path = pathlib.Path(args[3])
    if any(a["name"] == path.name for a in state["assets"]):
        raise SystemExit(88)
    state["assets"].append({"id": len(state["assets"])+1, "name":path.name, "size":path.stat().st_size,"state":"uploaded"})
    save()
    raise SystemExit(0)
if args[0] != "api":
    raise SystemExit(88)
route = next(arg for arg in args if arg.startswith("repos/"))
if "--method" in args:
    if not state.get("allowMutations"):
        raise SystemExit(88)
    method = args[args.index("--method")+1]
    if method == "POST" and route.endswith("/releases") and not state.get("releaseExists",True):
        state["releaseExists"] = True
    elif method == "PATCH" and route.endswith("/releases/1") and "draft=false" in args:
        state["release"]["draft"] = False
    else:
        raise SystemExit(88)
    value = state["release"]
    save()
elif route.endswith("/git/ref/tags/" + state["tag"]):
    value = {"object": {"type": state.get("tagType", "tag"), "sha": "a" * 40}}
elif "/git/tags/" in route:
    value = state["source"] if "--jq" in args else {"object": {"sha": state["source"]}}
elif route.endswith("/releases?per_page=100"):
    if state.get("discoveryError"):
        raise SystemExit(1)
    value = [[state["release"]]] if state.get("releaseExists",True) else [[]]
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
