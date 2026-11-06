
"""Demonstrate Duta's filesystem access and permission controls.

All operations take place inside an isolated temporary workspace.
No real project files are modified.
"""

from pathlib import Path
from tempfile import TemporaryDirectory

from duta import Duta, AccessDeniedError, UnsafePathError


def main():
    # Create an isolated workspace for the demonstration.
    with TemporaryDirectory() as temp_dir:
        root = Path(temp_dir)

        # Prepare example files.
        (root / "src").mkdir()
        (root / "src" / "main.py").write_text(
            "print('Hello from Duta!')\n",
            encoding="utf-8",
        )
        (root / "notes.txt").write_text(
            "This file has not been authorized.\n",
            encoding="utf-8",
        )
        (root / ".env").write_text(
            "API_KEY=example-secret\n",
            encoding="utf-8",
        )

        # Initialize Duta with the temporary workspace.
        duta = Duta(root)

        print("=" * 50)
        print("DUTA CAPABILITY DEMO")
        print("=" * 50)

        # DEMO 1: Grant read and list permissions.
        duta.allow("src/**/*.py", permissions=("list", "read"))
        print("\n[1] Granted read/list access to src/**/*.py")

        # DEMO 2: List authorized entries.
        print("\n[2] Listing authorized entries:")
        for entry in duta.tree():
            print(f"  {entry.kind}: {entry.path}")

        # DEMO 3: Read an authorized file.
        print("\n[3] Reading src/main.py:")
        print(duta.read("src/main.py"))

        # DEMO 4: Attempt unauthorized access.
        print("\n[4] Trying to read unauthorized notes.txt:")
        try:
            duta.read("notes.txt")
        except AccessDeniedError as error:
            print(f"  BLOCKED: {error}")

        # DEMO 5: Attempt to access a sensitive file.
        print("\n[5] Trying to read the excluded .env file:")
        try:
            duta.read(".env")
        except AccessDeniedError as error:
            print(f"  BLOCKED: {error}")

        # DEMO 6: Attempt path traversal.
        print("\n[6] Trying to escape the workspace:")
        try:
            duta.read("../outside.txt")
        except (AccessDeniedError, UnsafePathError) as error:
            print(f"  BLOCKED: {error}")

        # DEMO 7: Grant creation permission and create a file.
        print("\n[7] Creating a new file with Duta:")
        duta.allow("src/**/*.py", permissions=("create",))

        duta.create(
            "src/hello_duta.py",
            "print('Hello! This file was created by Duta.')\n",
        )
        print("Created: src/hello_duta.py")

        # DEMO 8: Read back the newly created file.
        print("\n[8] Reading the newly created file:")
        print(duta.read("src/hello_duta.py"))

        print("\n" + "=" * 50)
        print("DEMO COMPLETE")
        print("=" * 50)


if __name__ == "__main__":
    main()
