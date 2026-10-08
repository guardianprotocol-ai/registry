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
        check(f"subprocess call {checked} inherits the environment", "env" not in kwargs,
              str(sorted(kwargs)))
    check("subprocess.run calls were actually found to check", checked >= 1, str(checked))


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


def test_a_harness_reports_its_own_version():
    """A result whose harness version is unknown cannot be compared with next month's."""
    class Fake(targets.CliAgentTarget):
        name, executable = "fake", "fake-bin"

    def fake_run(argv, **kwargs):
        return FakeProc(stdout="fake-bin 2.1.274 (Fake Harness)\n")

    real = targets.subprocess.run
    targets.subprocess.run = fake_run
    try:
        check("a version is pulled out of the harness output", Fake().version() == "2.1.274",
              Fake().version())
    finally:
        targets.subprocess.run = real


def test_a_version_check_never_blocks_a_measurement():
    """Any failure gives 'unrecorded'. Measuring matters more than labelling."""
    class Fake(targets.CliAgentTarget):
        name, executable = "fake", "fake-bin"

    real = targets.subprocess.run
    try:
        targets.subprocess.run = lambda argv, **kw: FakeProc(stdout="", returncode=1)
        check("a non-zero exit gives unrecorded", Fake().version() == "unrecorded")
        targets.subprocess.run = lambda argv, **kw: FakeProc(stdout="no digits here")
        check("output with no version gives unrecorded", Fake().version() == "unrecorded")

        def boom(argv, **kw):
            raise OSError("not installed")
        targets.subprocess.run = boom
        check("a missing binary gives unrecorded", Fake().version() == "unrecorded")
    finally:
        targets.subprocess.run = real

    class NoFlag(targets.CliAgentTarget):
        name, executable, version_flag = "noflag", "x", None
    check("a harness with no version flag gives unrecorded",
          NoFlag().version() == "unrecorded")


def test_the_recorded_result_carries_the_harness_version():
    from guardian_scanner import results

    class FakeResult:
        pattern_id, target_name = "GP-0003", "claude-code"
        runs, successes, errors = 20, 20, 0

    class Fake:
        def version(self):
            return "9.9.9"

    folder = tempfile.mkdtemp()
    try:
        written = results.record([FakeResult()], folder, sensor_on=False,
                                 date="2026-10-08", commit="abc1234", target=Fake())
        doc = json.load(open(written[0]))
        check("the version reaches the result file",
              doc["target"]["harness_version"] == "9.9.9", str(doc["target"]))
        plain = results.record([FakeResult()], folder, sensor_on=False,
                               date="2026-10-08", commit="abc1234")
        doc = json.load(open(plain[0]))
        check("with no target it stays unrecorded rather than guessing",
              doc["target"]["harness_version"] == "unrecorded", str(doc["target"]))
    finally:
        shutil.rmtree(folder, ignore_errors=True)


def test_a_model_can_be_pinned_and_is_recorded_as_asked_for():
    """You can measure a model, but only the one you asked for, never a guess."""
    t = targets.claude_code(model="opus")
    argv = t.argv("hello", "/tmp/mcp.json")
    check("claude-code passes the model through", argv[-2:] == ["--model", "opus"], str(argv[-3:]))
    check("and records what was asked for", t.model_requested() == "opus")

    g = targets.gemini_cli(model="gemini-2.5-pro")
    check("gemini-cli uses its own flag",
          g.argv("hello", "/tmp/mcp.json")[-2:] == ["-m", "gemini-2.5-pro"],
          str(g.argv("hello", "/tmp/mcp.json")[-3:]))


def test_an_unpinned_harness_records_nothing_rather_than_guessing():
    t = targets.claude_code()
    check("no --model flag when none was asked for",
          "--model" not in t.argv("hello", "/tmp/mcp.json"))
    check("the model stays unknown", t.model_requested() is None)


def test_the_scripted_controls_have_no_model_at_all():
    for kind in ("vulnerable", "hardened"):
        t = targets.scripted(kind)
        check(f"scripted:{kind} reports no model", t.model_requested() == "none")
        check(f"scripted:{kind} cannot be pinned", t.supports_model is False)


def test_the_pinned_model_reaches_the_result_file():
    from guardian_scanner import results

    class FakeResult:
        pattern_id, target_name = "GP-0003", "claude-code"
        runs, successes, errors = 20, 20, 0

    class Pinned:
        def version(self): return "2.1.274"
        def model_requested(self): return "claude-opus-5"

    class Unpinned:
        def version(self): return "2.1.274"
        def model_requested(self): return None

    folder = tempfile.mkdtemp()
    try:
        doc = json.load(open(results.record([FakeResult()], folder, sensor_on=False,
                                            date="2026-10-08", target=Pinned())[0]))
        check("a pinned model is recorded",
              doc["target"]["model"] == "claude-opus-5", str(doc["target"]))
        check("and the harness version beside it",
              doc["target"]["harness_version"] == "2.1.274", str(doc["target"]))
        doc = json.load(open(results.record([FakeResult()], folder, sensor_on=False,
                                            date="2026-10-09", target=Unpinned())[0]))
        check("an unpinned run says unrecorded, not a guess",
              doc["target"]["model"] == "unrecorded", str(doc["target"]))
    finally:
        shutil.rmtree(folder, ignore_errors=True)


# ---------- the targets table ----------

def test_every_registered_target_can_be_built_and_reports_itself():
    from guardian_scanner import report
    rows = targets.available()
    check("the registry and the table agree",
          [r[0] for r in rows] == list(targets.REGISTRY), str([r[0] for r in rows]))
    for name, installed, credentials, note in rows:
        check(f"{name} reports installed as a bool", isinstance(installed, bool))
        check(f"{name} reports credentials as yes, no or unknown",
              credentials in (True, False, None), repr(credentials))
        check(f"{name} carries a note", bool(note), name)


def test_the_table_says_which_targets_measure_a_real_model():
    from guardian_scanner import report
    rows = [("scripted:vulnerable", True, True, "control"),
            ("claude-code", True, None, "costs tokens"),
            ("gemini-cli", True, False, "needs a key")]
    text = report.targets_text(rows, targets.WANTED)
    check("unknown credentials print as unknown", "unknown" in text, text[:200])
    check("a target needing a key is not counted ready", "2 of 3 ready" in text, text)
    check("it names what measures a real model", "Measures a real model: claude-code" in text, text)
    check("it says the scripted targets are the control",
          "control, not the finding" in text, text)


def test_the_table_shows_the_harnesses_nobody_has_written_yet():
    from guardian_scanner import report
    text = report.targets_text(targets.available(), targets.WANTED)
    for key, _ in targets.WANTED:
        check(f"{key} is listed as wanted", key in text, text[-400:])
    check("it points at the guide", "TEST_YOUR_AGENT.md" in text)


def test_a_target_with_nothing_ready_says_so_rather_than_implying_coverage():
    from guardian_scanner import report
    text = report.targets_text([("gemini-cli", False, False, "not installed")], ())
    check("no real model measured is stated plainly",
          "Nothing here measures a real model yet" in text, text)
    check("and it counts zero ready", "0 of 1 ready" in text, text)


def test_gemini_credentials_follow_the_environment():
    target = targets.gemini_cli()
    saved = {k: os.environ.pop(k, None)
             for k in ("GEMINI_API_KEY", "GOOGLE_GENAI_USE_VERTEXAI", "GOOGLE_GENAI_USE_GCA")}
    try:
        os.environ["GEMINI_API_KEY"] = "anything"
        check("a key in the environment counts as credentials", target.credentials() is True)
        del os.environ["GEMINI_API_KEY"]
        os.environ["GOOGLE_GENAI_USE_VERTEXAI"] = "1"
        check("vertex auth counts too", target.credentials() is True)
        del os.environ["GOOGLE_GENAI_USE_VERTEXAI"]
        check("credentials is a bool when it can be determined",
              isinstance(target.credentials(), bool))
    finally:
        for k, v in saved.items():
            if v is not None:
                os.environ[k] = v
            else:
                os.environ.pop(k, None)


def test_claude_code_does_not_guess_at_its_own_credentials():
    """It keeps its own session. Guessing would be worse than saying unknown."""
    check("claude-code reports unknown", targets.claude_code().credentials() is None)


def test_an_unregistered_target_is_refused_with_a_useful_message():
    from guardian_scanner import __main__ as cli
    try:
        cli._target("my-harness")
        ok, message = False, "accepted"
    except SystemExit as e:
        ok, message = True, str(e)
    check("an unknown target is refused", ok, message)
    check("the message points at the targets command",
          "guardian_scanner targets" in message, message)


# ---------- a harness that cannot pick its own model must be told one ----------

def test_the_class_table_covers_every_registry_entry():
    """A missing entry reads as 'this target requires nothing', which is the silent kind."""
    missing = sorted(set(targets.REGISTRY) - set(targets.CLASSES))
    check("every target in REGISTRY has a class in CLASSES", not missing, str(missing))
    extra = sorted(set(targets.CLASSES) - set(targets.REGISTRY))
    check("CLASSES names no target the registry does not offer", not extra, str(extra))
    for name, cls in sorted(targets.CLASSES.items()):
        built = targets.REGISTRY[name]()
        check(f"{name} builds the class CLASSES claims", isinstance(built, cls),
              f"{type(built).__name__} is not {cls.__name__}")


def test_gemini_requires_a_model_and_the_others_do_not():
    check("gemini-cli requires a model", targets.GeminiCliTarget.requires_model)
    for cls in (targets.ClaudeCodeTarget, targets.ScriptedTarget):
        check(f"{cls.__name__} does not require one",
              not getattr(cls, "requires_model", False))


def test_a_target_that_requires_a_model_offers_a_dated_example():
    """A list of blessed models rots exactly like a default. An example with a date does not."""
    for name, cls in sorted(targets.CLASSES.items()):
        if not getattr(cls, "requires_model", False):
            continue
        check(f"{name} names an example model", bool(cls.model_example), name)
        check(f"{name} says when that example was verified",
              bool(cls.model_verified_on), name)


def test_the_gemini_note_no_longer_claims_it_is_unverified():
    """It was verified on 2026-10-08. Leaving the old wording would understate the matrix."""
    note = targets.GeminiCliTarget.note
    check("the note does not say not yet verified", "not yet verified" not in note.lower(), note)
    check("the note says it was verified", "verified" in note.lower(), note)
    doc = targets.GeminiCliTarget.__doc__ or ""
    check("the docstring does not say not yet verified",
          "not yet verified" not in doc.lower(), doc[:200])


# ---------- the docs show commands that would actually run ----------

def test_documented_gemini_commands_name_a_model():
    """A target that refuses without --model must not be documented without one."""
    root = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    needs_model = sorted(n for n, c in targets.CLASSES.items()
                         if getattr(c, "requires_model", False))
    for doc in ("TEST_YOUR_AGENT.md", os.path.join("scanner", "README.md"),
                "START_HERE.md", "README.md"):
        path = os.path.join(root, doc)
        if not os.path.exists(path):
            continue
        for number, line in enumerate(open(path, encoding="utf-8").read().splitlines(), 1):
            if "guardian_scanner run" not in line:
                continue
            for name in needs_model:
                if f"--target {name}" in line:
                    check(f"{doc}:{number} names a model for {name}",
                          "--model" in line or line.rstrip().endswith("\\"),
                          line.strip()[:100])


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
