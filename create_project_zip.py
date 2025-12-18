#!/usr/bin/env python3
"""
Utility script to create a project zip while excluding development-only folders.
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import re
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path

EXCLUDED_DIRS = {".git", ".venv"}
ARCHIVE_PATTERN = re.compile(r"^\d{12}-vma\.zip$")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Create a zip archive of the repository while excluding .git and .venv, "
            "then move it to the desired destination."
        )
    )
    parser.add_argument(
        "destination",
        type=Path,
        help=(
            "Directory where the archive should be placed, or a full .zip file path "
            "that already follows yyyymmddhhmm-vma.zip."
        ),
    )
    return parser.parse_args()


def should_skip(relative_parts: tuple[str, ...]) -> bool:
    return any(part in EXCLUDED_DIRS for part in relative_parts)


def build_zip(base_path: Path, output_zip: Path) -> None:
    with zipfile.ZipFile(output_zip, "w", compression=zipfile.ZIP_DEFLATED) as zipf:
        for root, dirs, files in os.walk(base_path):
            rel_root = Path(root).relative_to(base_path)
            if should_skip(rel_root.parts):
                dirs[:] = []
                continue

            dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]
            for file_name in files:
                file_path = Path(root) / file_name
                if should_skip(file_path.relative_to(base_path).parts):
                    continue
                zipf.write(file_path, file_path.relative_to(base_path))


def resolve_destination_path(
    destination_arg: Path,
) -> Path:
    destination_arg = destination_arg.expanduser()
    if destination_arg.suffix == ".zip" or (
        destination_arg.exists() and destination_arg.is_file()
    ):
        if not ARCHIVE_PATTERN.match(destination_arg.name):
            raise ValueError(
                "Destination file must follow the yyyymmddhhmm-vma.zip pattern."
            )
        destination_arg.parent.mkdir(parents=True, exist_ok=True)
        return destination_arg

    destination_arg.mkdir(parents=True, exist_ok=True)
    filename = f"{dt.datetime.now():%Y%m%d%H%M}-vma.zip"
    return destination_arg / filename


def main() -> None:
    args = parse_args()
    project_root = Path(__file__).resolve().parent
    try:
        output_path = resolve_destination_path(args.destination)
    except ValueError as err:
        print(err, file=sys.stderr)
        sys.exit(1)
    with tempfile.TemporaryDirectory() as tmp_dir:
        temp_zip = Path(tmp_dir) / output_path.name
        build_zip(project_root, temp_zip)
        shutil.move(str(temp_zip), output_path)
    print(f"Archive created at {output_path}")


if __name__ == "__main__":
    main()
