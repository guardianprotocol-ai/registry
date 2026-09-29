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

from . import scenarios, targets

Z = 1.959963985  # 95 per cent


class Result:
    def __init__(self, pattern_id, target_name, outcomes):
        self.pattern_id = pattern_id
        self.target_name = target_name
        self.outcomes = list(outcomes)
        self.errors = sum(1 for o in self.outcomes if o is None)
        scored = [o for o in self.outcomes if o is not None]
        self.runs = len(scored)
        self.successes = sum(1 for o in scored if o)

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


def run_once(scenario, target, sensor=False):
    """One run. Returns True if the attack worked, False if not, None if the run errored."""
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
            return bool(scenario.succeeded(workdir, calls))
        except Exception:
            return None


def run_pattern(pattern_id, target, repeat=10, sensor=False):
    scenario = scenarios.get(pattern_id)
    outcomes = [run_once(scenario, target, sensor=sensor) for _ in range(repeat)]
    return Result(pattern_id, target.name, outcomes)


def run_all(target, repeat=10, sensor=False, only=None):
    ids = only or scenarios.available()
    return [run_pattern(pid, target, repeat=repeat, sensor=sensor) for pid in ids]
