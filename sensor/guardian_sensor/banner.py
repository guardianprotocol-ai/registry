"""A banner, on the two commands where somebody is looking at a screen.

Deliberately not a rendition of the mark. The brand rules say the mark is six nodes in a
fixed arrangement with exactly one amber, and not to add, move or redraw them. Every attempt
at fitting that into nine rows of characters moved the geometry to suit the grid, which is a
redraw whatever it is called. A wordmark with one lit node keeps the story the mark tells,
which is that one member catching an attack protects everyone, without claiming to be the
mark itself.

Printed only where somebody is reading: the command list, and the first screen of setup. Not
in the drill, the poll, or anything a service writes to a log, because a banner in a log is
noise that helps nobody and this runs from launchd far more often than from a terminal.

Python 3.9+ standard library only.
"""
from . import paint

# Guardian blue is the mark; signal amber is only ever the one lit node. The palette rules
# say never to use amber as a general accent, so here it marks exactly one character.
LIT = "\u25cf"
DIM = "\u25cb"
LIT_ASCII = "*"
DIM_ASCII = "o"


def _drawable(out):
    """Whether the terminal can render a filled circle.

    A terminal that cannot shows replacement characters, and mojibake where a logo should be
    is a worse first impression than no logo. Checked against the stream's own encoding
    rather than guessed from a locale variable.
    """
    encoding = getattr(out, "encoding", None) or "ascii"
    try:
        LIT.encode(encoding)
        DIM.encode(encoding)
        return True
    except (LookupError, UnicodeEncodeError):
        return False


def banner(out=None, subtitle=True):
    """The wordmark, with one node lit. A string, so it can be tested."""
    lit_ch, dim_ch = (LIT, DIM) if _drawable(out) else (LIT_ASCII, DIM_ASCII)
    nodes = "".join(dim_ch if i != 3 else lit_ch for i in range(6))
    if paint.enabled(out):
        lit = paint.paint(lit_ch, "warn", out)
        nodes = "".join(dim_ch if i != 3 else lit for i in range(6))
        name = paint.paint("GUARDIAN PROTOCOL", "bold", out)
    else:
        name = "GUARDIAN PROTOCOL"
    lines = ["", "  %s  %s" % (nodes, name)]
    if subtitle:
        lines.append("  %s  an open exchange for AI agent incidents"
                     % paint.paint("      ", "dim", out))
    lines.append("")
    return "\n".join(lines)


def show(out, subtitle=True):
    out.write(banner(out, subtitle) + "\n")
