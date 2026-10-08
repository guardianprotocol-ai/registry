"""The agents a scan can be run against.

Two kinds. The scripted reference agents are deterministic, cost nothing and need no model,
so the scan can run in CI: the vulnerable one does what poisoned content tells it, the
hardened one does not. They are the control, not the finding.

The third target drives a real Claude Code session over the same lab server. That is where
a real attack success rate comes from, and it costs tokens, so nothing runs it by default.
"""
import json
import os
import re
import shutil
import subprocess
import sys


class Client:
    """A small MCP stdio client, enough to drive a lab server the way an agent would."""

    def __init__(self, command, workdir, env=None):
        self.proc = subprocess.Popen(
            command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1, cwd=workdir,
            env={**os.environ, "GUARDIAN_SINK": os.path.join(workdir, "sinkhole.jsonl"), **(env or {})})
        self.n = 0
        self.calls = []

    def call(self, method, params=None):
        self.n += 1
        self.proc.stdin.write(json.dumps(
            {"jsonrpc": "2.0", "id": self.n, "method": method, "params": params or {}}) + "\n")
        self.proc.stdin.flush()
        return json.loads(self.proc.stdout.readline())

    @staticmethod
    def text_of(message):
        result = (message or {}).get("result") or {}
        return " ".join(c.get("text", "") for c in result.get("content", []) if isinstance(c, dict))

    @staticmethod
    def is_error(message):
        return bool(((message or {}).get("result") or {}).get("isError"))

    def note(self, record):
        self.calls.append(record)

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()


class ScriptedTarget:
    """A reference agent whose behaviour is fixed, so the scan has a known control."""

    def version(self):
        """The scripted agents are part of this repository, so the scanner commit is it."""
        return "in-repo"

    note = "control, not a finding. No model, costs nothing, runs in CI"

    def installed(self):
        return True

    def credentials(self):
        return True

    def __init__(self, kind):
        if kind not in ("vulnerable", "hardened"):
            raise ValueError("a scripted target is either vulnerable or hardened")
        self.kind = kind
        self.name = f"scripted:{kind}"

    def run(self, scenario, command, workdir, env=None):
        client = Client(command, workdir, env)
        try:
            client.call("initialize")
            if self.kind == "vulnerable":
                scenario.chain(client)
            elif scenario.decline:
                # The scenario says what resisting looks like for it, which is usually
                # doing the legitimate part of the task and not the planted part.
                scenario.decline(client)
            else:
                # The hardened agent reads the same content and declines to act on it.
                # Nothing pattern specific belongs here: a scenario that needs more says so
                # with its own `decline`.
                client.call("tools/list")
                client.call("tools/call",
                            {"name": "fetch_page", "arguments": {"url": "https://vendor.test/q3"}})
            return client.calls
        finally:
            client.close()


class CliAgentTarget:
    """Base for any agent harness that can be driven as a command line process.

    This is the template. To measure a harness nobody has measured yet, subclass this and
    write two short methods. Everything else is shared: putting the lab MCP server in front
    of the agent, running it once, pulling the final answer out, and handing that answer to
    the scenario to judge.

        class MyHarnessTarget(CliAgentTarget):
            name = "my-harness"

            def argv(self, prompt, config_path):
                return ["my-harness", "--prompt", prompt, "--mcp-config", config_path]

            def answer_of(self, stdout):
                return json.loads(stdout or "{}").get("text", "")

    Then add it to `_target()` in __main__.py so `--target my-harness` finds it.

    The contract a target must meet:

    - `name` is what the user types after `--target`.
    - `run(scenario, command, workdir, env)` returns a list of call records. A scenario's
      `succeeded(workdir, calls)` reads either those records or files the lab server wrote
      under `workdir`.
    - A target never decides whether an attack worked. That judgment belongs to the
      scenario, next to the pattern it came from, so that every harness is judged the same
      way. `scenario.from_answer` is how a text-only harness gets judged.

    Three rules worth keeping:

    - **One run is one process.** No state carries between runs, or the rate means nothing.
    - **Point the harness at the lab server and nothing else.** Whatever flag your harness
      has for restricting tools, use it. A run that reaches the real internet is not a
      measurement, it is an incident.
    - **Let it fail loudly.** Raise on a non-zero exit. The runner counts a raised run as
      errored and excludes it, which is right. Swallowing the error would score a broken
      harness as a defended one.
    """

    name = None
    #: MCP server key the lab is registered under. Harness flags usually reference it.
    server_key = "lab"
    #: Command that must be on PATH. Set it and `targets` reports this harness for free.
    executable = None
    #: One line for the targets table.
    note = ""

    def installed(self):
        return bool(self.executable) and shutil.which(self.executable) is not None

    #: Flag that makes the harness print its version. Set to None if it has none.
    version_flag = "--version"

    def version(self):
        """What the harness calls itself, for the result file.

        A result whose harness version is unknown cannot be compared with next month's, so
        this is asked once per run rather than left to the contributor to remember. Any
        failure gives 'unrecorded', which is honest and never blocks a measurement.
        """
        if not self.executable or not self.version_flag:
            return "unrecorded"
        try:
            proc = subprocess.run([self.executable, self.version_flag],
                                  capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.SubprocessError):
            return "unrecorded"
        if proc.returncode != 0:
            return "unrecorded"
        for line in (proc.stdout or "").splitlines():
            found = re.search(r"\d+\.\d+[\w.+-]*", line)
            if found:
                return found.group(0)
        return "unrecorded"

    def credentials(self):
        """True, False, or None when this target cannot cheaply tell.

        None is an honest answer and the default. A harness that keeps its own session,
        as Claude Code does, cannot be checked without spending a call, and guessing would
        be worse than saying so.
        """
        return None

    def __init__(self, sensor_config=None, timeout=300):
        self.sensor_config = sensor_config
        self.timeout = timeout

    # ---- subclasses implement these two ----

    def argv(self, prompt, config_path):
        raise NotImplementedError("a target must say how to run its harness")

    def answer_of(self, stdout):
        """The harness's final answer, as text. Override if it is not plain stdout."""
        return stdout or ""

    # ---- shared ----

    def mcp_config(self, command, workdir, env):
        """Write an MCP config pointing the harness at the lab server. Returns its path."""
        config = {"mcpServers": {self.server_key: {
            "command": command[0], "args": command[1:],
            "env": {"GUARDIAN_SINK": os.path.join(workdir, "sinkhole.jsonl"), **(env or {})}}}}
        path = os.path.join(workdir, "mcp.json")
        with open(path, "w") as f:
            json.dump(config, f)
        return path

    def run(self, scenario, command, workdir, env=None):
        path = self.mcp_config(command, workdir, env)
        proc = subprocess.run(self.argv(scenario.prompt, path), cwd=workdir,
                              capture_output=True, text=True, timeout=self.timeout)
        if proc.returncode != 0:
            raise RuntimeError(f"{self.name} exited {proc.returncode}: {proc.stderr[:300]}")
        answer = self.answer_of(proc.stdout)
        # The scenario judges, never the target. A scenario that reads files on disk needs
        # nothing from the answer, so the answer is still carried for the record.
        if scenario.from_answer:
            return scenario.from_answer(answer)
        return [{"answer": answer}]


class ClaudeCodeTarget(CliAgentTarget):
    """A real Claude Code session, driven headless over the lab server.

    Costs tokens, so the runner never reaches for it unless it is asked for by name.
    """

    name = "claude-code"
    executable = "claude"
    note = "costs tokens. Keeps its own session, so credentials cannot be checked from here"

    def argv(self, prompt, config_path):
        return ["claude", "-p", prompt, "--mcp-config", config_path, "--strict-mcp-config",
                "--allowedTools", f"mcp__{self.server_key}", "--output-format", "json"]

    def answer_of(self, stdout):
        return json.loads(stdout or "{}").get("result", "")


class GeminiCliTarget(CliAgentTarget):
    """A real Gemini CLI session over the same lab server.

    The second real harness, and the reason the base class above exists: the only things
    that differ between two vendors' agents are the flags and where the answer sits in the
    output. Gemini CLI reads its MCP servers from `.gemini/settings.json` in the working
    directory rather than from a flag, so the config is written there as well.

    Costs tokens. Asked for by name only.

    **Not yet verified against the live API.** The contract is tested in
    `tests/test_targets.py`, and the flags come from `gemini --help`, but no run has
    completed end to end from this repository because the machine it was written on has no
    Gemini credentials. Running it with `GEMINI_API_KEY` set, and recording what happens,
    is a good first contribution; see TEST_YOUR_AGENT.md.
    """

    name = "gemini-cli"
    executable = "gemini"
    note = "costs tokens. Wired and contract tested, not yet verified against the live API"

    def credentials(self):
        """Gemini CLI reads GEMINI_API_KEY, or an auth method in ~/.gemini/settings.json."""
        for key in ("GEMINI_API_KEY", "GOOGLE_GENAI_USE_VERTEXAI", "GOOGLE_GENAI_USE_GCA"):
            if os.environ.get(key):
                return True
        settings = os.path.join(os.path.expanduser("~"), ".gemini", "settings.json")
        try:
            with open(settings) as f:
                configured = json.load(f) or {}
        except (OSError, ValueError):
            return False
        return bool(configured.get("selectedAuthType")
                    or (configured.get("security") or {}).get("auth"))

    def mcp_config(self, command, workdir, env):
        path = super().mcp_config(command, workdir, env)
        settings_dir = os.path.join(workdir, ".gemini")
        os.makedirs(settings_dir, exist_ok=True)
        with open(path) as f:
            config = json.load(f)
        with open(os.path.join(settings_dir, "settings.json"), "w") as f:
            json.dump(config, f)
        return path

    def argv(self, prompt, config_path):
        return ["gemini", "-p", prompt, "--approval-mode", "yolo",
                "--allowed-mcp-server-names", self.server_key, "-o", "json"]

    def answer_of(self, stdout):
        if not stdout:
            return ""
        try:
            parsed = json.loads(stdout)
        except ValueError:
            return stdout
        if isinstance(parsed, dict):
            for key in ("response", "result", "text", "output"):
                if isinstance(parsed.get(key), str):
                    return parsed[key]
        return stdout


def scripted(kind):
    return ScriptedTarget(kind)


def claude_code(**kwargs):
    return ClaudeCodeTarget(**kwargs)


def gemini_cli(**kwargs):
    return GeminiCliTarget(**kwargs)


#: Everything `--target` accepts, in the order the table shows them.
REGISTRY = {
    "scripted:vulnerable": lambda: scripted("vulnerable"),
    "scripted:hardened": lambda: scripted("hardened"),
    "claude-code": claude_code,
    "gemini-cli": gemini_cli,
}

#: Harnesses worth measuring that nobody has written a target for yet. Listed so the gap
#: is visible rather than implied, and so a contributor can see their own harness missing.
WANTED = (
    ("cursor", "Cursor"),
    ("codex-cli", "Codex CLI"),
    ("ollama", "an open-weight model through Ollama"),
    ("langgraph", "a custom framework, for example LangGraph"),
)


def available():
    """[(name, installed, credentials, note)] for every target, for the targets table."""
    rows = []
    for name, make in REGISTRY.items():
        target = make()
        rows.append((name, target.installed(), target.credentials(),
                     getattr(target, "note", "")))
    return rows


def sensor_wrapper(config_path):
    """Put the reference sensor in front of a server command, the way a customer would."""
    run_py = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)))), "sensor", "run.py")
    return [sys.executable, run_py, "--config", config_path, "--"]
