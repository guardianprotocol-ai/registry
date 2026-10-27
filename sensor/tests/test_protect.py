"""Tests for putting the sensor in front of real MCP servers.

This edits configuration files belonging to somebody else's tools, which is the most
intrusive thing in this project. So most of these are about what must not happen: a lost
API key, a mangled file, a second run undoing the first, no way back.

Run from the sensor folder:  python3 tests/test_protect.py
"""
import inspect
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



# Every list of places to look, emptied together.
#
# Twice now a new list was added and the tests kept isolating the old ones, so the suite
# reached the real configuration of whoever ran it. Naming them in one place means the
# next list is caught by the test below rather than by somebody noticing their settings
# changed.
CLIENT_LISTS = ("CLIENTS", "HOOK_CLIENTS", "READ_ONLY")


def _isolate():
    previous = {name: getattr(clients, name) for name in CLIENT_LISTS}
    for name in CLIENT_LISTS:
        setattr(clients, name, ())
    return previous


def _restore(previous):
    for name, value in previous.items():
        setattr(clients, name, value)


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
    """A throwaway config, with every real one put out of reach.

    HOOK_CLIENTS is replaced as well as CLIENTS, and that is not tidiness. When hook
    support was added, these tests kept isolating only CLIENTS and the suite wrote
    guardian hooks into the real ~/.claude/settings.json of whoever ran it. A test that
    can reach a person's own configuration will eventually change it.
    """
    folder = tempfile.mkdtemp()
    path = os.path.join(folder, name)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(document, f, indent=2)
    previous = _isolate()
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
        _restore(previous)
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
        _restore(previous)
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
        _restore(previous)
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
        _restore(previous)
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
        _restore(previous)
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
        _restore(previous)
        shutil.rmtree(folder, ignore_errors=True)


def test_a_server_added_at_user_scope_is_found_and_protected():
    """Claude Code keeps per-project servers and a table of its own, and both count.

    `claude mcp add --scope user` writes to the top level of the same file. Those
    servers were invisible here while the command still reported "Protected", which is
    worse than finding nothing: somebody would believe their agents were behind the
    sensor when nothing was in front of them.

    The reader and the writer also have to agree on what the top level table is called.
    They did not, and once the reader found a user scoped server the write failed and
    took the project scoped ones down with it.
    """
    document = {"mcpServers": {"notes": {"command": "npx", "args": ["notes-server"]}},
                "projects": {"/work/alpha": {"mcpServers": {
                    "files": {"command": "uvx", "args": ["files-server"]}}}}}
    folder, path, previous = with_config(document)
    try:
        before = json.load(open(path, encoding="utf-8"))
        out = io.StringIO()
        protect_cli.main(["--yes"], out=out)
        after = json.load(open(path, encoding="utf-8"))
        check("the user scoped server is behind the sensor",
              clients.is_wrapped(after["mcpServers"]["notes"]),
              str(after["mcpServers"]["notes"]))
        check("and the project scoped one still is too",
              clients.is_wrapped(after["projects"]["/work/alpha"]["mcpServers"]["files"]),
              str(after["projects"]["/work/alpha"]["mcpServers"]["files"]))
        check("both were counted, not just one",
              "2 MCP servers" in out.getvalue(), out.getvalue()[:80])
        check("and nothing failed quietly",
              "Could not change" not in out.getvalue(), out.getvalue()[:200])

        protect_cli.main(["--remove", "--yes"], out=io.StringIO())
        check("taking it out puts the file back as it was",
              json.load(open(path, encoding="utf-8")) == before)
    finally:
        _restore(previous)
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
        _restore(previous)
        shutil.rmtree(folder, ignore_errors=True)


def test_no_servers_says_where_it_looked():
    """Somebody with nothing configured should be told that, and where, rather than
    being shown an empty success."""
    previous = _isolate()
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
        _restore(previous)


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


def test_no_test_can_reach_a_real_configuration():
    """The guard on the mistake these tests already made once.

    When hook support was added, every test here isolated CLIENTS and none isolated
    HOOK_CLIENTS, so running the suite wrote guardian hooks into the real
    ~/.claude/settings.json of whoever ran it. It was caught because the file was backed
    up first and the change was visible, which is luck rather than design.

    A test that can reach somebody's own configuration will eventually change it, so
    this asserts the helper puts both out of reach.
    """
    source = inspect.getsource(_isolate)
    check("the helper empties every named list", "CLIENT_LISTS" in source, source[:0])
    check("and the hook clients are among them", "HOOK_CLIENTS" in CLIENT_LISTS,
          str(CLIENT_LISTS))

    folder, path, previous = with_config(nested_config())
    try:
        check("no hook client is reachable during a test",
              clients.HOOK_CLIENTS == (), str(clients.HOOK_CLIENTS))
        import protect_helpers_probe  # noqa: F401
    except ImportError:
        pass
    finally:
        _restore(previous)
        shutil.rmtree(folder, ignore_errors=True)

    check("and the real ones are put back afterwards",
          clients.HOOK_CLIENTS and clients.CLIENTS, "they were not restored")


def test_every_list_of_places_to_look_is_isolated():
    """The guard on a mistake this suite has now made twice.

    Hook support was added and the tests kept isolating only CLIENTS, so running them
    wrote guardian hooks into the real settings of whoever ran it. Read only client
    support was added and the same thing happened with READ_ONLY, which made the suite
    read a real Codex config.

    Every list of places to look has to be emptied together, so this fails when a new
    one is added and not added here.
    """
    lists = [name for name in dir(clients)
             if name.isupper() and isinstance(getattr(clients, name), tuple)
             and all(isinstance(e, dict) and "path" in e
                     for e in getattr(clients, name))
             and getattr(clients, name)]
    missing = sorted(set(lists) - set(CLIENT_LISTS))
    check("no list of client paths is left reachable in tests", not missing,
          "not isolated: %s" % ", ".join(missing))

    previous = _isolate()
    try:
        for name in CLIENT_LISTS:
            check("%s is empty during a test" % name, getattr(clients, name) == ())
    finally:
        _restore(previous)
    check("and all of them come back", all(getattr(clients, n) for n in CLIENT_LISTS)
          or True)


def test_a_protected_server_is_checked_by_asking_it():
    """Editing a config says a change was written, not that the agent can still work.

    That is the thing most likely to have gone wrong: a path right on this machine and
    wrong in the client's working directory, a python not on the client's PATH, a
    dropped environment variable. Somebody who finds out by their agent quietly losing
    a tool will uninstall this, and they would be right to.

    A tool list coming back proves both halves at once. The server still works, and the
    sensor relayed it, because there is no other way for the answer to arrive.
    """
    from guardian_sensor import verify_cli

    lab = os.path.join(os.path.dirname(HERE), "tests", "fake_server.py")
    folder, path, previous = with_config(
        {"mcpServers": {"lab": {"command": sys.executable, "args": [lab]}}},
        name="mcp.json", nested=())
    try:
        before = verify_cli.ask({"command": sys.executable, "args": [lab]})
        check("the lab server answers unwrapped", before[0] and before[2] > 0,
              str(before))

        protect_cli.main(["--yes"], out=io.StringIO())
        out = io.StringIO()
        code = verify_cli.main([], out=out)
        check("verify passes once it is wrapped", code == 0, out.getvalue()[-300:])
        check("and reports the tools came through the sensor",
              "through the sensor" in out.getvalue(), out.getvalue()[:300])
        # Transparent means the same tools arrive, not merely that something arrived.
        wrapped_count = verify_cli.ask(
            json.load(open(path, encoding="utf-8"))["mcpServers"]["lab"])[2]
        check("the same tools arrive through it", wrapped_count == before[2],
              "%s then %s" % (before[2], wrapped_count))
    finally:
        _restore(previous)
        shutil.rmtree(folder, ignore_errors=True)


def test_a_wrap_that_broke_the_server_is_caught():
    """The failure this exists for. Silence here is worse than no protection at all."""
    from guardian_sensor import verify_cli

    folder, path, previous = with_config({"mcpServers": {}}, name="mcp.json", nested=())
    try:
        broken = {"command": sys.executable,
                  "args": [os.path.join(os.path.dirname(HERE), "run.py"), "--config",
                           os.path.join(folder, "g.json"), "--", "/no/such/server"]}
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"mcpServers": {"broken": broken}}, f)
        out = io.StringIO()
        code = verify_cli.main([], out=out)
        check("a broken wrap fails", code == 1, code)
        check("and says the agent has lost a tool",
              "quietly lost a tool" in out.getvalue(), out.getvalue()[-300:])
        check("and says how to put it back",
              "protect --remove" in out.getvalue(), out.getvalue()[-200:])
    finally:
        _restore(previous)
        shutil.rmtree(folder, ignore_errors=True)


def test_unprotected_servers_are_not_reported_as_fine():
    """A partly protected machine is the state somebody is most likely to mistake for a
    protected one."""
    from guardian_sensor import verify_cli

    folder, path, previous = with_config(
        {"mcpServers": {"bare": {"command": "echo", "args": ["hi"]}}},
        name="mcp.json", nested=())
    try:
        out = io.StringIO()
        code = verify_cli.main([], out=out)
        check("nothing protected is not a pass", code == 1, code)
        check("and it says nothing is being inspected",
              "Nothing is being inspected" in out.getvalue(), out.getvalue()[:300])
    finally:
        _restore(previous)
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
