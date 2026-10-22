"""Does the implementation conform to the specification?

The point of this file is the direction of the relationship. `hub.py` used to define the
sightings format by being the only thing that described it, which makes a format a tool. The
specification now defines it, and this asserts that the implementation satisfies the
specification rather than the other way round.

So every constant below is read from the spec files and compared against the code. A change
to the code that the spec does not sanction fails here, and so does a change to the spec that
the code has not implemented.

No dependencies: the JSON Schema is checked by a small validator covering the keywords this
schema actually uses, because the core is Python standard library only.

Run from the repository root:  python3 spec/tests/test_conformance.py
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
SPEC_DIR = os.path.join(ROOT, "spec")
sys.path.insert(0, os.path.join(ROOT, "sensor"))

from guardian_sensor import hub  # noqa: E402

failures = []


def check(name, condition, detail=""):
    print(f"{'ok  ' if condition else 'FAIL'} {name}{'' if condition else '  <- ' + detail}")
    if not condition:
        failures.append(name)


def schema():
    with open(os.path.join(SPEC_DIR, "sightings-0.2.schema.json"), encoding="utf-8") as f:
        return json.load(f)


def prose():
    with open(os.path.join(SPEC_DIR, "sightings-0.2.md"), encoding="utf-8") as f:
        return f.read()


# ---------- the implementation against the schema ----------

def test_the_field_list_matches():
    entry = schema()["$defs"]["entry"]
    check("the schema and the code agree on the field list",
          sorted(entry["properties"]) == sorted(hub.ALLOWED_FIELDS),
          f"{sorted(entry['properties'])} vs {sorted(hub.ALLOWED_FIELDS)}")
    check("the schema forbids any other field",
          entry.get("additionalProperties") is False, str(entry.get("additionalProperties")))


def test_the_vocabularies_match():
    props = schema()["$defs"]["entry"]["properties"]
    check("actions agree", sorted(props["action"]["enum"]) == sorted(hub.ACTIONS),
          f"{props['action']['enum']} vs {hub.ACTIONS}")
    check("sources agree", sorted(props["source"]["enum"]) == sorted(hub.SOURCES),
          f"{props['source']['enum']} vs {hub.SOURCES}")


def test_the_patterns_match():
    props = schema()["$defs"]["entry"]["properties"]
    pairs = [
        ("org", schema()["$defs"]["org"]["pattern"], hub.ORG_RE.pattern),
        ("hour", props["hour"]["pattern"], hub.HOUR_RE.pattern),
        ("rules_version", props["rules_version"]["pattern"], hub.RULES_VERSION_RE.pattern),
        ("sensor_version", props["sensor_version"]["pattern"], hub.SENSOR_VERSION_RE.pattern),
    ]
    for field, spec_pattern, code_pattern in pairs:
        # A character class may be written \d in Python and [0-9] in JSON Schema, which are
        # the same language. Compare what they accept, not how they are spelled.
        same = spec_pattern.replace("[0-9]", r"\d") == code_pattern.replace("[0-9]", r"\d")
        check(f"{field} accepts the same strings in both", same,
              f"{spec_pattern} vs {code_pattern}")
    check("pattern ids agree",
          props["pattern"]["pattern"].replace("[0-9]", r"\d") ==
          hub.PATTERN_RE.pattern.replace("[0-9]", r"\d"),
          f"{props['pattern']['pattern']} vs {hub.PATTERN_RE.pattern}")


def test_the_versions_match():
    versions = schema()["properties"]["schema_version"]["enum"]
    check("readable versions agree",
          sorted(versions) == sorted(hub.READABLE_SCHEMA_VERSIONS),
          f"{versions} vs {hub.READABLE_SCHEMA_VERSIONS}")
    check("the current version is one of them", hub.SCHEMA_VERSION in versions,
          hub.SCHEMA_VERSION)


def test_source_is_optional_in_the_schema_because_0_1_lacks_it():
    entry = schema()["$defs"]["entry"]
    check("source is not required, so a 0.1 document still validates",
          "source" not in entry["required"], str(entry["required"]))
    check("every other field is required",
          sorted(entry["required"]) == sorted(set(hub.ALLOWED_FIELDS) - {"source"}),
          str(entry["required"]))


# ---------- a produced document against the schema ----------

def validate(instance, node, path="$"):
    """Enough JSON Schema to check this schema. Returns a list of problems."""
    problems = []
    if "$ref" in node:
        ref = node["$ref"].split("/")[1:]
        target = schema()
        for part in ref:
            target = target[part]
        return validate(instance, target, path)
    kind = node.get("type")
    if kind == "object":
        if not isinstance(instance, dict):
            return [f"{path}: expected an object"]
        for key in node.get("required", []):
            if key not in instance:
                problems.append(f"{path}.{key}: required and missing")
        if node.get("additionalProperties") is False:
            for key in instance:
                if key not in node.get("properties", {}):
                    problems.append(f"{path}.{key}: field not in the specification")
        for key, sub in node.get("properties", {}).items():
            if key in instance:
                problems += validate(instance[key], sub, f"{path}.{key}")
    elif kind == "array":
        if not isinstance(instance, list):
            return [f"{path}: expected an array"]
        for i, item in enumerate(instance):
            problems += validate(item, node.get("items", {}), f"{path}[{i}]")
    elif kind == "string":
        if not isinstance(instance, str):
            return [f"{path}: expected a string"]
        if "pattern" in node and not re.search(node["pattern"], instance):
            problems.append(f"{path}: {instance!r} does not match {node['pattern']}")
    elif kind == "integer":
        if not isinstance(instance, int) or isinstance(instance, bool):
            return [f"{path}: expected an integer"]
        if "minimum" in node and instance < node["minimum"]:
            problems.append(f"{path}: {instance} below minimum {node['minimum']}")
    if "enum" in node and instance not in node["enum"]:
        problems.append(f"{path}: {instance!r} not one of {node['enum']}")
    return problems


def records(drill=False):
    out = []
    for pattern, action in (("GP-0001", "blocked"), ("GP-0003", "flagged")):
        rec = {"time": "2026-10-22T13:04:11+00:00", "patterns": [pattern],
               "action": action, "detail": {"tool": "send_message", "url": "https://x.test"}}
        if drill:
            rec["drill"] = True
        out.append(rec)
    return out


def test_what_the_implementation_produces_validates():
    doc = hub.build_sightings(records(), "acme-labs", "r2026.10.08")
    problems = validate(doc, schema())
    check("a produced document validates against the schema", not problems, str(problems))
    check("it declares the current version", doc["schema_version"] == hub.SCHEMA_VERSION,
          doc["schema_version"])
    check("entries say live when nothing was a drill",
          all(e["source"] == "live" for e in doc["sightings"]), str(doc["sightings"]))

    drill_doc = hub.build_sightings(records(drill=True), "acme-labs", "r2026.10.08")
    check("a drill document validates too", not validate(drill_doc, schema()),
          str(validate(drill_doc, schema())))
    check("and every entry is marked as a drill",
          all(e["source"] == "drill" for e in drill_doc["sightings"]),
          str(drill_doc["sightings"]))


def test_the_validator_itself_catches_a_bad_document():
    """A validator that passes everything would make the test above meaningless."""
    doc = hub.build_sightings(records(), "acme-labs", "r2026.10.08")
    doc["sightings"][0]["tool"] = "send_message"
    check("an extra field is refused", validate(doc, schema()), "validator passed it")
    doc = hub.build_sightings(records(), "acme-labs", "r2026.10.08")
    doc["sightings"][0]["hour"] = "2026-10-22T13:04:11"
    check("a too precise timestamp is refused", validate(doc, schema()), "validator passed it")
    doc = hub.build_sightings(records(), "acme-labs", "r2026.10.08")
    doc["sightings"][0]["source"] = "synthetic"
    check("a source outside the vocabulary is refused", validate(doc, schema()),
          "validator passed it")
    doc = hub.build_sightings(records(), "acme-labs", "r2026.10.08")
    doc["sightings"][0]["count"] = 0
    check("a count below one is refused", validate(doc, schema()), "validator passed it")


# ---------- the prose against the code ----------

def test_the_prose_lists_every_field_and_no_others():
    text = prose()
    for field in hub.ALLOWED_FIELDS:
        check(f"the spec documents {field}", f"`{field}`" in text)
    check("the spec states the three organization floor",
          "fewer than three distinct" in text, "floor not stated")
    check("the spec says a withheld row must still appear",
          "rather than omitting the row" in text, "omission not forbidden")
    check("the spec forbids mixing live and drill in one total",
          "must not mix" in text, "mixing not forbidden")


def test_the_aggregator_enforces_the_floor_the_spec_states():
    sys.path.insert(0, os.path.join(ROOT, "scripts"))
    import aggregate_sightings as agg
    check("the implemented floor is three", agg.MIN_ORGS == 3, str(agg.MIN_ORGS))


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
