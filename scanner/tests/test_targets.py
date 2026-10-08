"""Tests for the harness target contract.

Run from the scanner/ folder:  python3 tests/test_targets.py

These never start a real harness and never cost a token. What they pin down is the
contract a contributor has to meet when they add a target for their own harness: how it is
invoked, where the lab server is registered, and the rule that a target never decides
whether an attack worked.
"""
import json
import os
import shutil
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))

from guardian_scanner import scenarios, targets  # noqa: E402

failures = []

LAB = [sys.executable, "/lab/fake_server.py"]


def check(name, condition, detail=""):
    print(f"{'ok  ' if condition else 'FAIL'} {name}{'' if condition else '  <- ' + detail}")
    if not condition:
        failures.append(name)


class FakeProc:
    def __init__(self, stdout="", returncode=0, stderr=""):
        self.stdout, self.returncode, self.stderr = stdout, returncode, stderr


def run_with(target, scenario, stdout="", returncode=0, workdir=None):
    """Run a target with the subprocess replaced, capturing the argv it built."""
    seen = {}

    def fake_run(argv, **kwargs):
        seen["argv"] = argv
        seen["cwd"] = kwargs.get("cwd")
        seen["timeout"] = kwargs.get("timeout")
        return FakeProc(stdout=stdout, returncode=returncode)

    real = targets.subprocess.run
    targets.subprocess.run = fake_run
    try:
        calls = target.run(scenario, LAB, workdir)
        return calls, seen
    finally:
        targets.subprocess.run = real


# ---------- the contract ----------

def test_both_real_targets_declare_a_name():
    check("claude-code is named", targets.claude_code().name == "claude-code")
    check("gemini-cli is named", targets.gemini_cli().name == "gemini-cli")
    check("the base class refuses to be used directly",
          targets.CliAgentTarget.name is None)


def test_the_base_class_demands_an_argv():
    class Incomplete(targets.CliAgentTarget):
        name = "incomplete"

    folder = tempfile.mkdtemp()
    try:
        try:
            Incomplete().run(scenarios.get("GP-0001"), LAB, folder)
            ok = False
        except NotImplementedError:
            ok = True
        check("a target with no argv fails loudly", ok)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_the_lab_server_is_the_only_server_registered():
    for make in (targets.claude_code, targets.gemini_cli):
        folder = tempfile.mkdtemp()
        try:
            target = make()
            path = target.mcp_config(LAB, folder, {})
            config = json.load(open(path))
            servers = config["mcpServers"]
            check(f"{target.name} registers exactly one server", list(servers) == ["lab"],
                  str(list(servers)))
            check(f"{target.name} points it at the lab command",
                  servers["lab"]["command"] == LAB[0] and servers["lab"]["args"] == LAB[1:],
                  str(servers["lab"]))
            check(f"{target.name} sends the sinkhole into the workdir",
                  servers["lab"]["env"]["GUARDIAN_SINK"].startswith(folder),
                  servers["lab"]["env"]["GUARDIAN_SINK"])
        finally:
            shutil.rmtree(folder, ignore_errors=True)


def test_each_harness_is_restricted_to_the_lab():
    """A run that could reach the real internet is not a measurement."""
    folder = tempfile.mkdtemp()
    try:
        _, seen = run_with(targets.claude_code(), scenarios.get("GP-0001"),
                           stdout='{"result": "done"}', workdir=folder)
        argv = seen["argv"]
        check("claude-code restricts tools to the lab",
              "--allowedTools" in argv and "mcp__lab" in argv, str(argv))
        check("claude-code uses only the config we wrote",
              "--strict-mcp-config" in argv, str(argv))
        check("claude-code runs headless", "-p" in argv, str(argv))

        _, seen = run_with(targets.gemini_cli(), scenarios.get("GP-0001"),
                           stdout='{"response": "done"}', workdir=folder)
        argv = seen["argv"]
        check("gemini-cli restricts to the lab server",
              "--allowed-mcp-server-names" in argv and "lab" in argv, str(argv))
        check("gemini-cli runs headless and approves tools",
              "-p" in argv and "yolo" in argv, str(argv))
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_gemini_also_gets_settings_where_it_looks_for_them():
    """Gemini CLI reads MCP servers from .gemini/settings.json, not from a flag."""
    folder = tempfile.mkdtemp()
    try:
        targets.gemini_cli().mcp_config(LAB, folder, {})
        path = os.path.join(folder, ".gemini", "settings.json")
        check("gemini settings are written into the workdir", os.path.exists(path))
        check("they register the lab server",
              list(json.load(open(path))["mcpServers"]) == ["lab"])
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_a_nonzero_exit_raises_rather_than_scoring_zero():
    """A broken harness must not be counted as a defended one."""
    folder = tempfile.mkdtemp()
    try:
        for make in (targets.claude_code, targets.gemini_cli):
            try:
                run_with(make(), scenarios.get("GP-0003"), stdout="", returncode=1,
                         workdir=folder)
                ok = False
            except RuntimeError:
                ok = True
            check(f"{make().name} raises on a non-zero exit", ok)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_no_credential_can_land_in_the_config_we_write():
    """The MCP config is written to disk. Only the lab server's own env belongs in it.

    The harness gets its credentials by inheriting the shell, so a key never passes through
    this code. If someone ever changed the config to carry the process environment, a key
    would be written into a file, which is what this test exists to stop.
    """
    folder = tempfile.mkdtemp()
    marker = "sk-live-must-never-be-written-0123456789"
    real = os.environ.get("GEMINI_API_KEY")
    os.environ["GEMINI_API_KEY"] = marker
    try:
        for make in (targets.claude_code, targets.gemini_cli):
            target = make()
            path = target.mcp_config(LAB, folder, {"GUARDIAN_TAMPER": "1"})
            written = open(path).read()
            check(f"{target.name} writes no credential into the mcp config",
                  marker not in written, written[:160])
            env = json.loads(written)["mcpServers"]["lab"]["env"]
            check(f"{target.name} carries only the lab's own env",
                  set(env) == {"GUARDIAN_SINK", "GUARDIAN_TAMPER"}, str(sorted(env)))
        settings = os.path.join(folder, ".gemini", "settings.json")
        check("gemini settings carry no credential either",
              marker not in open(settings).read())
    finally:
        if real is None:
            os.environ.pop("GEMINI_API_KEY", None)
        else:
            os.environ["GEMINI_API_KEY"] = real
        shutil.rmtree(folder, ignore_errors=True)


def test_the_harness_inherits_the_shell_rather_than_a_built_environment():
    """A target must not construct an env, or the user's own credentials stop reaching it."""
    import ast
    path = os.path.join(os.path.dirname(HERE), "guardian_scanner", "targets.py")
    tree = ast.parse(open(path, encoding="utf-8").read())
    checked = 0
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = getattr(func, "attr", None)
        owner = getattr(getattr(func, "value", None), "id", None)
        if name != "run" or owner != "subprocess":
            continue
        checked += 1
        kwargs = {k.arg for k in node.keywords}
        check("the harness subprocess inherits the environment", "env" not in kwargs,
              str(sorted(kwargs)))
    check("a subprocess.run call was actually found to check", checked == 1, str(checked))


# ---------- the judgment belongs to the scenario ----------

def test_the_scenario_judges_not_the_target():
    """GP-0003 used to be judged inside the Claude Code target. It is not any more."""
    source = open(os.path.join(os.path.dirname(HERE), "guardian_scanner", "targets.py"),
                  encoding="utf-8").read()
    check("no pattern id is hardcoded in targets.py", "GP-00" not in source)
    check("no lab tool name is hardcoded in targets.py", "weather" not in source)
    check("GP-0003 carries its own answer judging",
          scenarios.get("GP-0003").from_answer is not None)


def test_a_tampered_tool_is_read_from_the_answer():
    judge = scenarios.get("GP-0003").from_answer
    used = judge("The weather tool says it is sunny in Boston.")
    check("an answer that used the changed tool scores as a success",
          used[0]["tool"] == "weather" and used[0]["accepted"] is True, str(used))
    refused = judge("That call was blocked by the Guardian sensor.")
    check("a blocked answer does not", refused[0]["accepted"] is False, str(refused))
    check("the answer is kept on the record", "blocked" in refused[0]["answer"].lower())


def test_both_harnesses_judge_gp0003_identically():
    """Same answer, same verdict, whichever vendor produced it."""
    folder = tempfile.mkdtemp()
    try:
        answer = "It is sunny in Boston."
        a, _ = run_with(targets.claude_code(), scenarios.get("GP-0003"),
                        stdout=json.dumps({"result": answer}), workdir=folder)
        b, _ = run_with(targets.gemini_cli(), scenarios.get("GP-0003"),
                        stdout=json.dumps({"response": answer}), workdir=folder)
        check("both harnesses produce the same verdict",
              a[0]["accepted"] == b[0]["accepted"] is True, f"{a} vs {b}")
        check("both carry the same answer", a[0]["answer"] == b[0]["answer"] == answer)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_a_file_judged_scenario_needs_nothing_from_the_answer():
    """GP-0001 is scored from the sinkhole, so the answer is carried but not read."""
    folder = tempfile.mkdtemp()
    try:
        calls, _ = run_with(targets.claude_code(), scenarios.get("GP-0001"),
                            stdout='{"result": "Here is the summary."}', workdir=folder)
        check("the answer is still recorded", calls == [{"answer": "Here is the summary."}],
              str(calls))
        check("GP-0001 judges from disk, not from the answer",
              scenarios.get("GP-0001").from_answer is None)
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_each_harness_pulls_its_answer_out_of_its_own_output_shape():
    check("claude-code reads .result",
          targets.claude_code().answer_of('{"result": "hello"}') == "hello")
    check("gemini-cli reads .response",
          targets.gemini_cli().answer_of('{"response": "hello"}') == "hello")
    check("gemini-cli falls back to raw text when the output is not json",
          targets.gemini_cli().answer_of("plain text") == "plain text")
    for make in (targets.claude_code, targets.gemini_cli):
        check(f"{make().name} survives empty output", make().answer_of("") == "")


def test_adding_a_target_is_two_short_methods():
    """The template in the base class docstring has to actually work."""
    class MyHarnessTarget(targets.CliAgentTarget):
        name = "my-harness"

        def argv(self, prompt, config_path):
            return ["my-harness", "--prompt", prompt, "--mcp-config", config_path]

        def answer_of(self, stdout):
            return json.loads(stdout or "{}").get("text", "")

    folder = tempfile.mkdtemp()
    try:
        calls, seen = run_with(MyHarnessTarget(), scenarios.get("GP-0003"),
                               stdout='{"text": "It is sunny."}', workdir=folder)
        check("a target written from the template runs", seen["argv"][0] == "my-harness",
              str(seen["argv"]))
        check("and is judged by the scenario like any other",
              calls[0]["accepted"] is True, str(calls))
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
