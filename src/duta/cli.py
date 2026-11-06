"""Command-line interface for Duta."""

import argparse
import sys
from pathlib import Path

from duta.config import (
    add_permission,
    initialize_config,
    load_config,
)
from duta.core import Duta, DutaError


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def get_workspace(workspace: str) -> Path:
    """Resolve and validate the selected workspace directory."""

    root = Path(workspace).expanduser().resolve(strict=True)

    if not root.is_dir():
        raise ValueError(f"Workspace is not a directory: {root}")

    return root


def get_duta(workspace: str) -> tuple[Path, Duta]:
    """
    Load saved configuration and build a Duta instance.

    Every command uses this helper so permission rules are applied
    consistently instead of being repeated throughout the CLI.
    """

    root = get_workspace(workspace)

    # A workspace must be initialized before other operations can use it.
    config = load_config(root)

    # Create the filesystem core for this workspace.
    duta = Duta(root)

    # Apply all saved permission rules to the core enforcement layer.
    for rule in config["permissions"]:
        duta.allow(
            rule["pattern"],
            permissions=rule["permissions"],
        )

    return root, duta


def print_error(error: Exception) -> int:
    """Print a consistent error message and return a failure exit code."""

    print(f"Error: {error}", file=sys.stderr)
    return 1


# ---------------------------------------------------------------------------
# Command handlers
# ---------------------------------------------------------------------------

def handle_init(workspace: str) -> int:
    """Initialize Duta inside the selected workspace."""

    try:
        root = get_workspace(workspace)

        # Initialize an empty configuration without overwriting an existing one.
        config_file = initialize_config(root)

        print("Duta initialized successfully.")
        print(f"Workspace: {root}")
        print(f"Configuration: {config_file}")
        print("Permissions: None granted")

        return 0

    except (DutaError, OSError, ValueError) as error:
        return print_error(error)


def handle_grant(
    workspace: str,
    pattern: str,
    permissions: list[str],
) -> int:
    """Save permissions for a workspace-relative path pattern."""

    try:
        root = get_workspace(workspace)

        # Validate and persist the requested permission rule.
        config_file = add_permission(root, pattern, permissions)

        print("Permissions updated successfully.")
        print(f"Workspace: {root}")
        print(f"Pattern: {pattern}")
        print(f"Permissions: {', '.join(permissions)}")
        print(f"Configuration: {config_file}")

        return 0

    except (DutaError, OSError, ValueError) as error:
        return print_error(error)


def handle_permissions(workspace: str) -> int:
    """Display the permission rules saved for a workspace."""

    try:
        root = get_workspace(workspace)
        config = load_config(root)

        print()
        print("Duta Permissions")
        print("=" * 30)
        print(f"Workspace: {root}")

        rules = config["permissions"]

        if not rules:
            print("\nNo permissions configured.")
            return 0

        for index, rule in enumerate(rules, start=1):
            print(f"\n{index}. Pattern: {rule['pattern']}")
            print(
                f"   Permissions: {', '.join(rule['permissions'])}"
            )

        print()
        return 0

    except (DutaError, OSError, ValueError) as error:
        return print_error(error)


def handle_inspect(workspace: str) -> int:
    """List files and directories permitted by the saved rules."""

    try:
        root, duta = get_duta(workspace)

        entries = duta.tree()

        files = [
            entry for entry in entries
            if entry.kind == "file"
        ]

        directories = [
            entry for entry in entries
            if entry.kind == "directory"
        ]

        print()
        print("Duta Workspace Inspector")
        print("=" * 30)
        print(f"Workspace: {root}")
        print(f"Authorized files: {len(files)}")
        print(f"Authorized directories: {len(directories)}")

        if not entries:
            print("\nNo entries matched the listing permissions.")
        else:
            print("\nAuthorized entries:")

            for entry in entries:
                if entry.kind == "directory":
                    print(f"  [DIR]  {entry.path}")
                else:
                    print(
                        f"  [FILE] {entry.path} "
                        f"({entry.size_bytes} bytes)"
                    )

        print()
        return 0

    except (DutaError, OSError, ValueError) as error:
        return print_error(error)


def handle_read(
    workspace: str,
    relative_path: str,
) -> int:
    """Read an authorized UTF-8 text file."""

    try:
        root, duta = get_duta(workspace)

        # The core verifies read permission before returning the content.
        content = duta.read(relative_path)

        print(content, end="" if content.endswith("\n") else "\n")

        return 0

    except (DutaError, OSError, ValueError) as error:
        return print_error(error)


def handle_create(
    workspace: str,
    relative_path: str,
    content: str,
) -> int:
    """Create a new file without overwriting an existing file."""

    try:
        root, duta = get_duta(workspace)

        # The core checks create permission and rejects existing targets.
        duta.create(relative_path, content)

        print("File created successfully.")
        print(f"Path: {relative_path}")
        print(f"Workspace: {root}")

        return 0

    except (DutaError, OSError, ValueError) as error:
        return print_error(error)


def handle_edit(
    workspace: str,
    relative_path: str,
    content: str,
) -> int:
    """Replace the contents of an existing file when authorized."""

    try:
        root, duta = get_duta(workspace)

        # The core checks edit permission and validates the existing file.
        duta.edit(relative_path, content)

        print("File edited successfully.")
        print(f"Path: {relative_path}")
        print(f"Workspace: {root}")

        return 0

    except (DutaError, OSError, ValueError) as error:
        return print_error(error)


# ---------------------------------------------------------------------------
# Argument parser and command routing
# ---------------------------------------------------------------------------

def main() -> int:
    """Parse command-line arguments and execute the selected command."""

    parser = argparse.ArgumentParser(
        prog="duta",
        description=(
            "Duta — permission-controlled access to local project files."
        ),
    )

    parser.add_argument(
        "--version",
        action="version",
        version="Duta 0.1.0",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        help="Available Duta commands.",
    )

    # Initialize a workspace.
    init_parser = subparsers.add_parser(
        "init",
        help="Initialize Duta in a workspace.",
    )

    init_parser.add_argument(
        "workspace",
        nargs="?",
        default=".",
        help="Workspace directory (defaults to the current directory).",
    )

    # Inspect authorized files and directories.
    inspect_parser = subparsers.add_parser(
        "inspect",
        help="Inspect authorized workspace entries.",
    )

    inspect_parser.add_argument(
        "workspace",
        nargs="?",
        default=".",
        help="Workspace directory (defaults to the current directory).",
    )

    # Grant permissions to a relative glob pattern.
    grant_parser = subparsers.add_parser(
        "grant",
        help="Grant permissions to a file pattern.",
    )

    grant_parser.add_argument(
        "pattern",
        help="Workspace-relative glob pattern.",
    )

    grant_parser.add_argument(
        "--permissions",
        nargs="+",
        choices=["list", "read", "create", "edit"],
        required=True,
        help="Permissions to grant.",
    )

    grant_parser.add_argument(
        "--workspace",
        default=".",
        help="Workspace directory (defaults to the current directory).",
    )

    # Display saved permission rules.
    permissions_parser = subparsers.add_parser(
        "permissions",
        help="Display saved permission rules.",
    )

    permissions_parser.add_argument(
        "workspace",
        nargs="?",
        default=".",
        help="Workspace directory (defaults to the current directory).",
    )

    # Read an authorized text file.
    read_parser = subparsers.add_parser(
        "read",
        help="Read an authorized text file.",
    )

    read_parser.add_argument(
        "path",
        help="Workspace-relative path of the file to read.",
    )

    read_parser.add_argument(
        "--workspace",
        default=".",
        help="Workspace directory (defaults to the current directory).",
    )

    # Create a new file when authorized.
    create_parser = subparsers.add_parser(
        "create",
        help="Create a new file when authorized.",
    )

    create_parser.add_argument(
        "path",
        help="Workspace-relative path of the new file.",
    )

    create_parser.add_argument(
        "--content",
        required=True,
        help="Text content to write into the new file.",
    )

    create_parser.add_argument(
        "--workspace",
        default=".",
        help="Workspace directory (defaults to the current directory).",
    )

    # Edit an existing file when authorized.
    edit_parser = subparsers.add_parser(
        "edit",
        help="Replace an existing file's contents when authorized.",
    )

    edit_parser.add_argument(
        "path",
        help="Workspace-relative path of the existing file.",
    )

    edit_parser.add_argument(
        "--content",
        required=True,
        help="Replacement text for the existing file.",
    )

    edit_parser.add_argument(
        "--workspace",
        default=".",
        help="Workspace directory (defaults to the current directory).",
    )

    # Parse the user's command.
    args = parser.parse_args()

    # Route the selected command to its handler.
    if args.command == "init":
        return handle_init(args.workspace)

    if args.command == "grant":
        return handle_grant(
            args.workspace,
            args.pattern,
            args.permissions,
        )

    if args.command == "permissions":
        return handle_permissions(args.workspace)

    if args.command == "inspect":
        return handle_inspect(args.workspace)

    if args.command == "read":
        return handle_read(
            args.workspace,
            args.path,
        )

    if args.command == "create":
        return handle_create(
            args.workspace,
            args.path,
            args.content,
        )

    if args.command == "edit":
        return handle_edit(
            args.workspace,
            args.path,
            args.content,
        )

    # Show help when the user runs 'duta' without a command.
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())