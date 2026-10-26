"""Tests for putting the sensor in front of real MCP servers.

This edits configuration files belonging to somebody else's tools, which is the most
intrusive thing in this project. So most of these are about what must not happen: a lost
API key, a mangled file, a second run undoing the first, no way back.

Run from the sensor folder:  python3 tests/test_protect.py
"""
import io
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
from guardian_sensor import clients, protect_cli  # noqa: E402

failures = []
SECRET = "sk-this-must-never-be-printed"


def check(name, condition, detail=""):
    print(f"{'ok  ' if condition else 'FAIL'} {name}{'' if condition else '  <- ' + str(detail)}")
    if not condition:
        failures.append(name)


def nested_config():
    """Claude Code's shape: servers under one key per project, beside other settings."""
    return {"numStartups": 42,
            "projects": {
                "/work/alpha": {
                    "mcpServers": {"files": {
                        "command": "npx",
                        "args": ["-y", "server-filesystem", "/work/alpha"],
                        "env": {"API_TOKEN": SECRET}}},
                    "allowedTools": ["Bash"]},
                "/work/beta": {"mcpServers": {}}}}


def with_config(document, name=".claude.json", nested=("projects",)):
    folder = tempfile.mkdtemp()
    path = os.path.join(folder, name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(document, f, indent=2)
    previous = clients.CLIENTS
    clients.CLIENTS = ({"name": "test-client", "path": path, "nested": nested,
                        "key": "mcpServers", "note": ""},)
    return folder, path, previous


def test_wrapping_keeps_everything_it_is_not_changing():
    """A config file holds more than servers, and losing any of it is unforgivable."""
    folder, path, previous = with_config(nested_config())
    try:
        protect_cli.main(["--yes"], out=io.StringIO())
        after = json.load(open(path, encoding="utf-8"))
        entry = after["projects"]["/work/alpha"]["mcpServers"]["files"]
        check("the server is behind the sensor", clients.is_wrapped(entry), str(entry))
        check("its environment survives", entry["env"]["API_TOKEN"] == SECRET)
        check("settings beside it survive", after["numStartups"] == 42)
        check("settings beside the table survive",
              after["projects"]["/work/alpha"]["allowedTools"] == ["Bash"])
        check("a project with no servers is untouched",
              after["projects"]["/work/beta"]["mcpServers"] == {})
    finally:
        clients.CLIENTS = previous
        shutil.rmtree(folder, ignore_errors=True)


def test_a_copy_is_made_before_anything_is_written():
    folder, path, previous = with_config(nested_config())
    try:
        protect_cli.main(["--yes"], out=io.StringIO())
        copies = [f for f in os.listdir(folder) if ".guardian-backup-" in f]
        check("the file was copied first", len(copies) == 1, str(os.listdir(folder)))
        original = json.load(open(os.path.join(folder, copies[0]), encoding="utf-8"))
        check("and the copy is the file as it was",
              not clients.is_wrapped(
                  original["projects"]["/work/alpha"]["mcpServers"]["files"]))
    finally:
        clients.CLIENTS = previous
        shutil.rmtree(folder, ignore_errors=True)


def test_running_it_twice_does_nothing_the_first_run_did_not():
    """Somebody will run this again. Wrapping a wrapped server would bury the real
    command one layer deeper every time and eventually nothing would start."""
    folder, path, previous = with_config(nested_config())
    try:
        protect_cli.main(["--yes"], out=io.StringIO())
        first = json.load(open(path, encoding="utf-8"))
        out = io.StringIO()
        protect_cli.main(["--yes"], out=out)
        again = json.load(open(path, encoding="utf-8"))
        check("the file is unchanged", first == again)
        check("and it says so", "already protected" in out.getvalue().lower(),
              out.getvalue()[:160])
    finally:
        clients.CLIENTS = previous
        shutil.rmtree(folder, ignore_errors=True)


def test_there_is_a_way_back():
    folder, path, previous = with_config(nested_config())
    try:
        before = nested_config()["projects"]["/work/alpha"]["mcpServers"]["files"]
        protect_cli.main(["--yes"], out=io.StringIO())
        protect_cli.main(["--remove", "--yes"], out=io.StringIO())
        after = json.load(open(path, encoding="utf-8"))
        check("the server is exactly as it started",
              after["projects"]["/work/alpha"]["mcpServers"]["files"] == before,
              str(after["projects"]["/work/alpha"]["mcpServers"]["files"]))
    finally:
        clients.CLIENTS = previous
        shutil.rmtree(folder, ignore_errors=True)


def test_nothing_is_written_when_only_asked_to_look():
    folder, path, previous = with_config(nested_config())
    try:
        before = open(path, encoding="utf-8").read()
        out = io.StringIO()
        protect_cli.main(["--print-only"], out=out)
        check("the file is untouched", open(path, encoding="utf-8").read() == before)
        check("and it says nothing was written",
              "Nothing was written" in out.getvalue(), out.getvalue()[-200:])
    finally:
        clients.CLIENTS = previous
        shutil.rmtree(folder, ignore_errors=True)


def test_a_secret_is_never_printed():
    """An env block routinely holds API keys. Showing one to prove it was preserved
    would be a poor trade."""
    folder, path, previous = with_config(nested_config())
    try:
        out = io.StringIO()
        protect_cli.main(["--print-only"], out=out)
        shown = out.getvalue()
        check("the token does not appear", SECRET not in shown, shown[:200])
        check("but the person is told it is kept",
              "environment variable" in shown, shown[:400])
    finally:
        clients.CLIENTS = previous
        shutil.rmtree(folder, ignore_errors=True)


def test_a_flat_config_works_too():
    """Desktop, Cursor and Windsurf keep one table rather than one per project."""
    folder, path, previous = with_config(
        {"mcpServers": {"db": {"command": "uvx", "args": ["mcp-server-postgres"]}}},
        name="mcp.json", nested=())
    try:
        protect_cli.main(["--yes"], out=io.StringIO())
        entry = json.load(open(path, encoding="utf-8"))["mcpServers"]["db"]
        check("a flat table is wrapped", clients.is_wrapped(entry), str(entry))
        check("and unwraps to what it was",
              clients.unwrap(entry)["command"] == "uvx", str(clients.unwrap(entry)))
    finally:
        clients.CLIENTS = previous
        shutil.rmtree(folder, ignore_errors=True)


def test_no_servers_says_where_it_looked():
    """Somebody with nothing configured should be told that, and where, rather than
    being shown an empty success."""
    previous = clients.CLIENTS
    clients.CLIENTS = ({"name": "nowhere", "path": "/does/not/exist.json",
                        "nested": (), "key": "mcpServers", "note": ""},)
    try:
        out = io.StringIO()
        code = protect_cli.main([], out=out)
        check("it exits cleanly", code == 0, code)
        check("it says none were found",
              "No MCP servers found" in out.getvalue(), out.getvalue()[:160])
        check("and lists where it looked",
              "/does/not/exist.json" in out.getvalue(), out.getvalue()[:400])
    finally:
        clients.CLIENTS = previous


def test_it_starts_in_monitor_mode():
    """The first thing a sensor does to somebody's real work must not be to stop it.
    A false positive on day one is how a security tool gets uninstalled on day one."""
    folder = tempfile.mkdtemp()
    try:
        path, made = protect_cli.ensure_config(folder)
        check("settings are created", made and os.path.exists(path))
        settings = json.load(open(path, encoding="utf-8"))
        check("and it records rather than blocks", settings["mode"] == "monitor",
              str(settings))
        _, again = protect_cli.ensure_config(folder)
        check("and are not overwritten on a later run", not again)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def main():
    for fn in [v for k, v in sorted(globals().items()) if k.startswith("test_")]:
        fn()
    print()
    if failures:
        print(f"FAIL ({len(failures)}): {', '.join(failures)}")
        sys.exit(1)
    print("PASS")


if __name__ == "__main__":
    main()
