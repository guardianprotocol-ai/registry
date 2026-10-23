"""Tests for the banner.

The thing it must not do is pretend to be the mark. The brand rules say the mark is six
nodes in a fixed arrangement with exactly one amber, and not to add, move or redraw them.
Several attempts at fitting that into nine rows of characters each moved the geometry to suit
the grid, which is a redraw whatever it is called, so this is a wordmark with one lit node
instead.

Run from the sensor folder:  python3 tests/test_banner.py
"""
import io
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from guardian_sensor import banner  # noqa: E402

failures = []


def check(name, condition, detail=""):
    print(f"{'ok  ' if condition else 'FAIL'} {name}{'' if condition else '  <- ' + detail}")
    if not condition:
        failures.append(name)


class Stream:
    """A stand-in stream. StringIO will not let its encoding be set, and the thing under
    test reads exactly that attribute."""

    def __init__(self, encoding="utf-8", tty=False):
        self.encoding = encoding
        self._tty = tty
        self.written = []

    def isatty(self):
        return self._tty

    def write(self, text):
        self.written.append(text)
        return len(text)


def test_exactly_one_node_is_lit():
    """The story the mark tells is that one member catching an attack protects everyone.
    Two lit nodes, or none, is a different story."""
    line = banner.banner(Stream()).splitlines()[1]
    check("six nodes", line.count(banner.LIT) + line.count(banner.DIM) == 6, line)
    check("exactly one is lit", line.count(banner.LIT) == 1, line)
    check("the other five are not", line.count(banner.DIM) == 5, line)


def test_it_falls_back_when_the_terminal_cannot_draw():
    """Mojibake where a logo should be is a worse first impression than no logo."""
    ascii_line = banner.banner(Stream(encoding="ascii")).splitlines()[1]
    check("a plain terminal gets plain characters",
          banner.LIT not in ascii_line and banner.DIM not in ascii_line, ascii_line)
    check("and still exactly one lit",
          ascii_line.count(banner.LIT_ASCII) == 1, ascii_line)
    check("and still six nodes",
          ascii_line.count(banner.LIT_ASCII) + ascii_line.count(banner.DIM_ASCII) == 6,
          ascii_line)
    unknown = banner.banner(io.StringIO()).splitlines()[1]
    check("a stream with no encoding falls back too",
          banner.LIT not in unknown, unknown)
    weird = banner.banner(Stream(encoding="no-such-codec")).splitlines()[1]
    check("an unknown codec does not raise", banner.LIT not in weird, weird)


def test_no_escape_codes_unless_somebody_is_watching():
    plain = banner.banner(Stream(tty=False))
    check("a pipe gets no colour", "\033[" not in plain, repr(plain))
    lit = banner.banner(Stream(tty=True))
    check("a terminal does", "\033[" in lit, repr(lit))
    check("and the amber is on the lit node only",
          lit.count("\033[33m") == 1, repr(lit))


def test_it_says_what_this_is():
    text = banner.banner(Stream())
    check("the name is there", "GUARDIAN PROTOCOL" in text, text)
    check("and what it is for", "AI agent incidents" in text, text)
    check("the subtitle can be left off",
          "AI agent incidents" not in banner.banner(Stream(), subtitle=False))


def test_it_is_not_printed_where_a_service_would_log_it():
    """This runs from launchd and systemd far more often than from a terminal, and a banner
    in a service log is noise that helps nobody."""
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for module in ("agenda.py", "drill.py", "enroll.py", "report" ):
        path = os.path.join(root, "guardian_sensor", module)
        if not os.path.exists(path):
            continue
        body = open(path, encoding="utf-8").read()
        check(f"{module} does not print the banner", "banner" not in body,
              f"{module} imports banner")


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
