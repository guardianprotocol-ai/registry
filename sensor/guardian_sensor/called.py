"""How this was invoked, so printed commands match what the reader typed."""
import os
import sys


def invocation():
    """`./guardian`, `guardian`, or the module form, whichever they used.

    Printing the form somebody did not type is a small way of telling them the tool was
    written for a different person, and these messages exist to be copied.
    """
    told = os.environ.get("GUARDIAN_INVOCATION")
    if told:
        return told
    if os.path.basename(sys.argv[0] or "") == "guardian":
        return "guardian"
    return "python3 -m guardian_sensor"
