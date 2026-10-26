"""Where a member's own records live. One answer, used by everything.

There were four. `enroll`, `share` and `status` each read GUARDIAN_HOME and fell back to
`~/.guardian`, in three separate copies of the same six lines. `drill` did not read it at
all and wrote to `.guardian/drill` relative to wherever it was run.

That is not a tidiness problem. A member who sets GUARDIAN_HOME, which is the documented
answer for a locked down corporate machine, had their drill write to one directory and
their sharing read from another. The drill reported three attacks caught and the send that
followed reported nothing to send, and both were telling the truth about different
directories.

Records also stay out of the clone. `git clean -xfd` would destroy them, and an operator
telling somebody to "just pull" would be asking them to risk their own evidence.
"""
import os

DIR_NAME = ".guardian"
OVERRIDE = "GUARDIAN_HOME"


def data_dir(explicit=None):
    """The folder holding this member's records, as an absolute path.

    An explicit path always wins, because a caller that passed one asked for it. Otherwise
    GUARDIAN_HOME, which exists for a participant whose home directory is managed and
    locked down. Otherwise ~/.guardian.

    Read every time rather than captured at import, so a test or a service that sets the
    variable gets the directory it set rather than the one that existed when the module
    was first loaded.
    """
    if explicit:
        return os.path.abspath(explicit)
    override = os.environ.get(OVERRIDE)
    if override:
        return os.path.abspath(override)
    return os.path.join(os.path.expanduser("~"), DIR_NAME)


def drill_dir(explicit=None):
    """Where the fire drill keeps its own evidence, beside the sensor's."""
    return os.path.join(data_dir(explicit), "drill")


def evidence_paths(explicit=None):
    """Both logs a report is built from: the proxy's, and the drill's."""
    root = data_dir(explicit)
    return (os.path.join(root, "evidence.jsonl"),
            os.path.join(root, "drill", "evidence.jsonl"))


def path(*parts):
    """A file under the member's data directory, resolved when it is called.

    Every default that used to be written as ".guardian/<name>" relative to the current
    directory goes through here. Relative defaults meant the answer depended on where the
    command was typed: a proxy started inside a project wrote its evidence into that
    project, while a report read the member's home and found nothing. Live detections, the
    ones the exchange exists for, were the data most likely to be stranded.
    """
    return os.path.join(data_dir(), *parts)
