"""Entry point for `python3 -m guardian_sensor`."""
import sys

from .sensor import main

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        # Somebody pressing Ctrl-C answered the question. Showing them a traceback for
        # it suggests they broke something, which is a poor thing to tell a person whose
        # first instinct when unsure was to back out.
        sys.stderr.write("\nStopped. Nothing was installed and nothing was sent.\n")
        sys.exit(130)
    except BrokenPipeError:
        # Piping into head or less closes the pipe early. That is the pipe working.
        sys.exit(0)
