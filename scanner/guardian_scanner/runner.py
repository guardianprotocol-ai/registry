"""Run a pattern's test many times and report an attack success rate.

Agents do not behave the same way twice. Running a test once tells you what happened once,
which is why the result here is a rate with an interval around it and never a pass or a
fail. A run that errored is excluded from the rate rather than scored as a success, so a
broken harness cannot look like a defended agent.
"""
import json
import math
import os
import tempfile
import time

from . import scenarios, targets

Z = 1.959963985  # 95 per cent

# An answer is agent output, so it is kept short and checked for secrets before publishing.
MAX_ANSWER = 2000


class Run:
    """One run and the evidence the judge was given.

    A rate built from bare booleans cannot be re-judged later: `successes: 20` is a number
    someone typed, and a judge bug looks identical to a real finding. Keeping the calls and
    the final answer means a reader can recount the rate and see what the judge keyed on.
    """

    def __init__(self, n, outcome, calls=None, answer=None, seconds=0.0, error=None):
        self.n = n
        self.outcome = outcome          # True, False, or None for an errored run
        self.calls = calls or []
        self.answer = answer
        self.seconds = seconds
        self.error = error

    @property
    def state(self):
        return "errored" if self.outcome is None else ("success" if self.outcome else "defended")

    def as_dict(self):
        answer = self.answer
        truncated = False
        if isinstance(answer, str) and len(answer) > MAX_ANSWER:
            answer, truncated = answer[:MAX_ANSWER], True
        out = {"n": self.n, "outcome": self.state, "seconds": round(self.seconds, 2)}
        # The calls are what the judge actually read, minus the answer, which is kept once.
        # Empty entries are dropped: a side effect judge reads the workdir, not the calls,
        # and recording "[{}]" says nothing while looking like it should.
        judged_on = [d for d in ({k: v for k, v in c.items() if k != "answer"}
                                 for c in self.calls) if d]
        if judged_on:
            out["judged_on"] = judged_on
        if answer is not None:
            out["answer"] = answer
            if truncated:
                out["answer_truncated_from"] = len(self.answer)
        if self.error:
            out["error"] = self.error
        return out


class Result:
    def __init__(self, pattern_id, target_name, outcomes):
        self.pattern_id = pattern_id
        self.target_name = target_name
        # Accepts Run records or bare booleans, so older callers and tests keep working.
        self.log = [o if isinstance(o, Run) else Run(i + 1, o)
                    for i, o in enumerate(outcomes)]
        self.outcomes = [r.outcome for r in self.log]
        self.errors = sum(1 for o in self.outcomes if o is None)
        scored = [o for o in self.outcomes if o is not None]
        self.runs = len(scored)
        self.successes = sum(1 for o in scored if o)

    @property
    def run_log(self):
        return [r.as_dict() for r in self.log]

    @property
    def rate(self):
        return self.successes / self.runs if self.runs else 0.0

    @property
    def interval(self):
        """Wilson score interval. With no runs it is the whole range, which is the truth."""
        n = self.runs
        if n == 0:
            return (0.0, 1.0)
        p = self.successes / n
        denom = 1 + Z * Z / n
        centre = (p + Z * Z / (2 * n)) / denom
        half = Z * math.sqrt(p * (1 - p) / n + Z * Z / (4 * n * n)) / denom
        return (max(0.0, centre - half), min(1.0, centre + half))

    def as_dict(self):
        low, high = self.interval
        return {"pattern": self.pattern_id, "target": self.target_name, "runs": self.runs,
                "successes": self.successes, "attack_success_rate": round(self.rate, 4),
                "interval_95": [round(low, 4), round(high, 4)], "errors": self.errors}


def _sensor_config(workdir):
    path = os.path.join(workdir, "guardian.json")
    with open(path, "w") as f:
        json.dump({"mode": "block", "allowlist": ["example.com"],
                   "pins_path": os.path.join(workdir, "pins.json"),
                   "evidence_path": os.path.join(workdir, "evidence.jsonl")}, f)
    return path


def run_once(scenario, target, sensor=False, n=1):
    """One run, as a Run record: the verdict plus the evidence the judge saw."""
    started = time.time()
    with tempfile.TemporaryDirectory() as workdir:
        command = scenario.server_command()
        if sensor:
            command = targets.sensor_wrapper(_sensor_config(workdir)) + command
        try:
            if scenario.warmup and sensor:
                # The operator approves the tool as it stands. This is what the sensor pins,
                # and it costs nothing, because approval is not something the agent does.
                warm = targets.Client(command, workdir)
                try:
                    warm.call("initialize")
                    warm.call("tools/list")
                finally:
                    warm.close()
            env = {"GUARDIAN_TAMPER": "1"} if scenario.tamper else {}
            calls = target.run(scenario, command, workdir, env)
            outcome = bool(scenario.succeeded(workdir, calls))
            answer = next((c.get("answer") for c in calls if c.get("answer") is not None), None)
            return Run(n, outcome, calls=calls, answer=answer, seconds=time.time() - started)
        except Exception as e:
            # Errored runs leave the denominator, and the reason is kept so a run of zeros
            # caused by a broken harness cannot be mistaken for a defended agent.
            return Run(n, None, seconds=time.time() - started,
                       error=f"{type(e).__name__}: {str(e)[:200]}")


def run_pattern(pattern_id, target, repeat=10, sensor=False):
    scenario = scenarios.get(pattern_id)
    outcomes = [run_once(scenario, target, sensor=sensor, n=i + 1) for i in range(repeat)]
    return Result(pattern_id, target.name, outcomes)


def run_all(target, repeat=10, sensor=False, only=None):
    ids = only or scenarios.available()
    return [run_pattern(pid, target, repeat=repeat, sensor=sensor) for pid in ids]
