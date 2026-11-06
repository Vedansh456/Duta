"""Load, validate, and manage Duta workspace configuration."""

import json
import os
import tempfile
from pathlib import Path


# Duta stores its settings inside each workspace.
CONFIG_DIR = ".duta"
CONFIG_FILE = "config.json"

# These are the operations that Duta currently supports.
SUPPORTED_PERMISSIONS = {"list", "read", "create", "edit"}


def config_path(workspace: str | Path) -> Path:
    """Return the configuration file path for an existing workspace."""
    root = Path(workspace).expanduser().resolve(strict=True)

    if not root.is_dir():
        raise ValueError(f"Workspace is not a directory: {root}")

    return root / CONFIG_DIR / CONFIG_FILE


def validate_config(config: dict) -> dict:
    """Validate the structure and contents of a Duta configuration."""

    if not isinstance(config, dict):
        raise ValueError("Configuration must be a JSON object.")

    if config.get("version") != 1:
        raise ValueError("Unsupported or missing configuration version.")

    rules = config.get("permissions")

    if not isinstance(rules, list):
        raise ValueError("'permissions' must be a list.")

    for rule in rules:
        if not isinstance(rule, dict):
            raise ValueError("Each permission rule must be an object.")

        if set(rule) != {"pattern", "permissions"}:
            raise ValueError(
                "Each rule must contain only 'pattern' and 'permissions'."
            )

        pattern = rule["pattern"]

        if not isinstance(pattern, str) or not pattern.strip():
            raise ValueError("Permission patterns must be non-empty strings.")

        # Normalize Windows separators before checking the pattern.
        normalized = pattern.replace("\\", "/").strip()

        # Patterns must be relative to the workspace.
        if normalized.startswith("/") or (
            len(normalized) > 1 and normalized[1] == ":"
        ):
            raise ValueError("Permission patterns must be relative paths.")

        if ".." in normalized.split("/"):
            raise ValueError("Permission patterns cannot contain '..'.")

        rule_permissions = rule["permissions"]

        if not isinstance(rule_permissions, list) or not rule_permissions:
            raise ValueError(
                "Each rule must contain a non-empty permissions list."
            )

        if not all(
            isinstance(permission, str)
            for permission in rule_permissions
        ):
            raise ValueError("Permissions must be strings.")

        if len(set(rule_permissions)) != len(rule_permissions):
            raise ValueError("Duplicate permissions are not allowed.")

        unknown = set(rule_permissions) - SUPPORTED_PERMISSIONS

        if unknown:
            raise ValueError(
                f"Unsupported permissions: {', '.join(sorted(unknown))}"
            )

    # Return the original configuration after validation.
    return config


def save_config(workspace: str | Path, config: dict) -> Path:
    """Save a validated configuration using an atomic file replacement."""

    validate_config(config)
    path = config_path(workspace)
    path.parent.mkdir(parents=True, exist_ok=True)

    # Write to a temporary file in the same directory first.
    # This reduces the risk of leaving a partially written configuration.
    temporary_path = None

    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            dir=path.parent,
            prefix=".config-",
            suffix=".tmp",
            delete=False,
        ) as temporary_file:
            temporary_path = Path(temporary_file.name)
            json.dump(config, temporary_file, indent=4)
            temporary_file.write("\n")

        # Replace the old configuration only after writing succeeds.
        os.replace(temporary_path, path)

    finally:
        # Remove a leftover temporary file if writing or replacement fails.
        if temporary_path is not None and temporary_path.exists():
            temporary_path.unlink()

    return path


def initialize_config(workspace: str | Path) -> Path:
    """Initialize Duta without overwriting an existing configuration."""

    path = config_path(workspace)

    # Start with no permissions.
    config = {
        "version": 1,
        "permissions": [],
    }

    path.parent.mkdir(parents=True, exist_ok=True)

    # Exclusive creation prevents overwriting an existing file.
    with path.open("x", encoding="utf-8", newline="") as file:
        json.dump(config, file, indent=4)
        file.write("\n")

    return path


def load_config(workspace: str | Path) -> dict:
    """Load and validate an existing Duta configuration."""

    path = config_path(workspace)

    if not path.is_file():
        raise FileNotFoundError(
            f"Duta is not initialized in this workspace: "
            f"{Path(workspace).resolve()}"
        )

    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as error:
        raise ValueError(
            f"Invalid JSON configuration in {path}"
        ) from error

    return validate_config(config)


def add_permission(
    workspace: str | Path,
    pattern: str,
    permissions: list[str],
) -> Path:
    """Add permissions to a pattern, preserving existing configuration."""

    # Validate the new rule before changing the saved configuration.
    candidate_rule = {
        "pattern": pattern,
        "permissions": permissions,
    }

    validate_config({
        "version": 1,
        "permissions": [candidate_rule],
    })

    # An existing configuration is required before permissions can be added.
    config = load_config(workspace)

    # Normalize separators so equivalent Windows paths are consistent.
    normalized_pattern = pattern.replace("\\", "/").strip()

    # If this exact pattern already exists, merge permissions into it.
    for rule in config["permissions"]:
        existing_pattern = rule["pattern"].replace("\\", "/").strip()

        if existing_pattern == normalized_pattern:
            combined = set(rule["permissions"])
            combined.update(permissions)

            rule["permissions"] = sorted(combined)

            return save_config(workspace, config)

    # Otherwise, create a new rule.
    config["permissions"].append({
        "pattern": normalized_pattern,
        "permissions": sorted(set(permissions)),
    })

    return save_config(workspace, config)