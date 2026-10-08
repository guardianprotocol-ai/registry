"""The proxy must survive the ways a wrapped MCP server misbehaves.

The sensor sits between a real client and a real server, so a fault here does not just fail
a test: it takes out the server the contributor was using. Each case below was a real defect.

Run from the sensor/ folder:  python3 tests/test_shutdown.py
"""
import json
import os
import signal
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)
from guardian_sensor import sensor  # noqa: E402

MESSAGE = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/list"}) + "\n"
STUBBORN = "import sys, time\nfor line in sys.stdin: pass\ntime.sleep(600)\n"
DIES = "import sys\nsys.exit(0)\n"
ECHO = ("import sys, json\n"
        "for line in sys.stdin:\n"
        "    try: m = json.loads(line)\n"
        "    except Exception: continue\n"
        "    sys.stdout.write(json.dumps({'jsonrpc':'2.0','id':m.get('id'),'result':{}})+'\\n')\n"
        "    sys.stdout.flush()\n")

failures = []


def check(name, condition, detail=""):
    print(f"{'ok  ' if condition else 'FAIL'} {name}{'' if condition else '  <- ' + detail}")
    if not condition:
        failures.append(name)


def run_proxy(server_src, stdin_text, tmp, name, timeout=30):
    path = os.path.join(tmp, f"{name}.py")
    with open(path, "w", encoding="utf-8") as f:
        f.write(server_src)
    p = subprocess.run([sys.executable, os.path.join(ROOT, "run.py"), "--", sys.executable, path],
                       input=stdin_text, capture_output=True, text=True, timeout=timeout)
    return p, path


def test_a_server_command_that_does_not_exist_is_explained():
    p = subprocess.run([sys.executable, os.path.join(ROOT, "run.py"), "--", "/no/such/server"],
                       input=MESSAGE, capture_output=True, text=True, timeout=30)
    check("a missing server command is not a stack trace", "Traceback" not in p.stderr, p.stderr[:200])
    check("the message names the command", "/no/such/server" in p.stderr, p.stderr[:200])
    check("the message says where to look", "after --" in p.stderr, p.stderr[:200])


def test_a_server_that_ignores_stdin_close_is_stopped_not_orphaned():
    """It used to raise TimeoutExpired out of main and leave the server running."""
    import tempfile
    tmp = tempfile.mkdtemp()
    try:
        p, path = run_proxy(STUBBORN, MESSAGE, tmp, "stubborn")
        check("the proxy exits cleanly", p.returncode == 0, f"exit {p.returncode}: {p.stderr[:160]}")
        check("no stack trace reaches the client", "Traceback" not in p.stderr, p.stderr[:200])
        check("it says the server had to be stopped",
              "did not exit" in p.stderr, p.stderr[:200])
        time.sleep(0.5)
        left = subprocess.run(["pgrep", "-f", path], capture_output=True, text=True)
        pids = [x for x in left.stdout.split() if x]
        check("the server is not left running as an orphan", not pids, str(pids))
        for pid in pids:
            try:
                os.kill(int(pid), signal.SIGKILL)
            except Exception:
                pass
    finally:
        import shutil
        shutil.rmtree(tmp, ignore_errors=True)


def test_a_server_that_exits_immediately_does_not_crash_the_relay():
    import shutil
    import tempfile
    tmp = tempfile.mkdtemp()
    try:
        p, _ = run_proxy(DIES, MESSAGE * 200, tmp, "dies")
        check("a dead server does not crash the proxy", p.returncode == 0,
              f"exit {p.returncode}: {p.stderr[:160]}")
        check("no broken pipe reaches the client",
              "BrokenPipeError" not in p.stderr, p.stderr[:200])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_the_healthy_path_is_unchanged():
    import shutil
    import tempfile
    tmp = tempfile.mkdtemp()
    try:
        p, _ = run_proxy(ECHO, MESSAGE, tmp, "echo")
        check("a healthy server still round trips", p.returncode == 0 and '"result"' in p.stdout,
              f"exit {p.returncode}, stdout {p.stdout[:120]}")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def test_shut_down_reports_the_exit_status_of_a_well_behaved_server():
    proc = subprocess.Popen([sys.executable, "-c", "import sys\nfor line in sys.stdin: pass\n"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
    code = sensor._shut_down(proc)
    check("a server that exits on stdin close returns its status", code == 0, str(code))


def test_the_relay_stops_instead_of_raising_on_a_closed_pipe():
    """pump writes outside its try on purpose, so a closed pipe must end the loop."""
    class Closed:
        def write(self, _):
            raise BrokenPipeError(32, "Broken pipe")

        def flush(self):
            pass

    sensor.pump(iter([MESSAGE]), Closed(), lambda m: None, None)
    check("a closed destination ends the relay without raising", True)


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
