"""Entry point for `python -m win_event_triage`."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
