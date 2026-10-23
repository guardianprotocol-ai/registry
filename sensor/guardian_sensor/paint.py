"""Colour, when there is somebody there to see it.

A drill prints caught or MISSED down a column, and the one that matters should be findable
without reading. That is the whole ambition here.

Off whenever it would be noise: a pipe, a file, a log, a terminal that says it cannot, or an
operator who said not to. A tool that writes escape codes into a service log has made the log
worse to help nobody, and this one is run from launchd and systemd far more often than from a
terminal.

Python 3.9+ standard library only.
"""
import os
import sys

CODES = {"good": "\033[32m", "bad": "\033[31m", "warn": "\033[33m",
         "dim": "\033[2m", "bold": "\033[1m"}
RESET = "\033[0m"


def enabled(stream=None):
    """Whether to colour at all.

    NO_COLOR is honoured because it is the convention and because somebody who set it meant
    it. FORCE_COLOR exists for the case where output is piped on purpose and the reader still
    wants it.
    """
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if os.environ.get("TERM") in ("dumb", ""):
        return False
    stream = stream if stream is not None else sys.stdout
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError):
        return False


def paint(text, kind, stream=None):
    """`text` in the colour for `kind`, or exactly `text` when colour is off."""
    if kind not in CODES or not enabled(stream):
        return text
    return "%s%s%s" % (CODES[kind], text, RESET)
