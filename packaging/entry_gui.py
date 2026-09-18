"""PyInstaller entry point for the windowed build."""
import multiprocessing
import sys

from filterscope.gui import main

if __name__ == "__main__":
    multiprocessing.freeze_support()
    sys.exit(main())
