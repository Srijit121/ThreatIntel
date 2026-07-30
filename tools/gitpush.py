#!/usr/bin/env python3

import subprocess
import sys
from datetime import datetime
from pathlib import Path

# Repository path
REPO_PATH = Path("/home/srijit/Project/ThreatIntel")


def run(command):
    """Run a shell command and stop on failure."""
    print(f"\n➜ {' '.join(command)}")

    result = subprocess.run(
        command,
        cwd=REPO_PATH,
        text=True,
    )

    if result.returncode != 0:
        sys.exit(result.returncode)


def has_changes():
    """Return True if there are uncommitted changes."""
    result = subprocess.run(
        ["git", "status", "--porcelain"],
        cwd=REPO_PATH,
        capture_output=True,
        text=True,
    )

    return bool(result.stdout.strip())


def main():
    print("=" * 50)
    print(" ThreatIntel Git Auto Push")
    print("=" * 50)

    if not has_changes():
        print("\n✅ No changes to commit.")
        return

    commit_message = f"Auto update {datetime.now():%Y-%m-%d %H:%M:%S}"

    run(["git", "add", "."])
    run(["git", "commit", "-m", commit_message])
    run(["git", "push"])

    print("\n✅ Repository successfully pushed to GitHub!")


if __name__ == "__main__":
    main()
