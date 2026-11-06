# Duta

**A free, local-first, permission-controlled bridge between AI applications and local filesystems.**

Duta is an open-source Python library and integration layer that enables AI applications to discover and interact with files on a user's local machine through explicitly granted permissions.

It provides a model-independent foundation for connecting AI systems to local project files without requiring a Duta-operated cloud service or a specific AI model provider.

## Why Duta?

AI applications can reason about files and projects, but accessing a user's local filesystem introduces important challenges:

- How can an AI application discover relevant project files?
- How can file access be restricted to explicitly authorized locations?
- How can an application read, create, and edit files without unrestricted filesystem access?
- How can different AI applications use the same local filesystem interface?

Duta addresses these challenges through a local-first filesystem core, a permission system, and standardized integration interfaces.

## Core principles

**Local-first:** Files remain on the user's machine. Duta does not require users to upload their projects to a Duta cloud service.

**Permission-controlled:** Access is governed by explicit permission rules. An AI application does not automatically receive unrestricted filesystem access.

**Model-independent:** Duta is not tied to a particular LLM or model provider. It provides an integration layer that different AI applications can use.

**User-controlled:** Users determine the workspace and the permissions granted to applications.

**Free and reusable:** Duta is designed as a reusable Python package without mandatory paid infrastructure or a Duta-operated account.

## Architecture

Duta consists of three main layers:

1. **Filesystem Core**
   - Workspace initialization.
   - File and directory discovery.
   - Authorized file reading.
   - Authorized file creation.
   - Authorized file editing.
   - Path validation and sensitive-file exclusions.

2. **Permission Layer**
   - Explicit access rules.
   - Permission checks for individual operations.
   - Separate permissions for listing, reading, creating, and editing.
   - Restrictions on sensitive files and unsafe paths.

3. **Integration Layer**
   - Python library interface.
   - Command-line interface.
   - Model-independent MCP server.
   - Local standard-input/output and Streamable HTTP transports.
   - OAuth-based authentication for remote MCP connectivity.

MCP is one integration interface provided by Duta. It is not the entirety of the project.

## Installation

Duta requires Python 3.10 or newer.

Once the package is published on PyPI:

```bash
pip install duta-bridge
```

To install from a cloned source repository:

```bash
git clone <YOUR_GITHUB_REPOSITORY_URL>
cd Duta

python -m venv .venv
```

Activate the environment:

**Windows PowerShell**
```powershell
.venv\Scripts\Activate.ps1
```

**Linux/macOS**
```bash
source .venv/bin/activate
```

Install Duta:

```bash
python -m pip install -e .
```

## Python API

Duta can be used directly as a Python library.

### Initialize a workspace

```python
from duta import Duta, AccessDeniedError

# Restrict Duta to a specific project workspace.
duta = Duta("./my-project")

# Grant permission to list and read Python files.
duta.allow(
    "src/**/*.py",
    permissions=("list", "read")
)

# Discover authorized files.
for entry in duta.tree():
    print(entry.kind, entry.path)

# Read an authorized file.
try:
    content = duta.read("src/main.py")
    print(content)

except AccessDeniedError as error:
    print("Access blocked:", error)
```

### Create a file

```python
# Grant explicit creation permission.
duta.allow(
    "src/**/*.py",
    permissions=("create",)
)

duta.create(
    "src/new_feature.py",
    "print('Created using Duta!')\n"
)
```

### Edit an existing file

```python
# Grant explicit editing permission.
duta.allow(
    "src/**/*.py",
    permissions=("edit",)
)

duta.edit(
    "src/main.py",
    "print('Updated using Duta!')\n"
)
```

Creation and editing are separate operations with separate permissions. Creating a file does not silently overwrite an existing file, and editing does not silently create a missing file.

## Command-line interface

Duta includes a command-line interface for workspace management and filesystem operations.

Available commands:

| Command | Purpose |
|---|---|
| `duta init` | Initialize Duta in a workspace |
| `duta inspect` | Inspect authorized workspace entries |
| `duta grant` | Grant permissions to file patterns |
| `duta permissions` | Display saved permission rules |
| `duta read` | Read an authorized text file |
| `duta create` | Create a file when authorized |
| `duta edit` | Edit an existing file when authorized |

To see the complete command syntax:

```powershell
duta --help
```

To check the installed version:

```powershell
duta --version
```

## MCP integration

Duta includes an MCP server that allows compatible AI applications to interact with its filesystem capabilities through the Model Context Protocol.

Two transport modes are supported.

### 1. Standard input/output (stdio)

```powershell
duta-mcp --workspace "D:\Projects\MyProject" --transport stdio
```

This mode is suitable for local MCP clients that launch and communicate with Duta as a subprocess.

### 2. Streamable HTTP

```powershell
duta-mcp --workspace "D:\Projects\MyProject" --transport streamable-http --host 127.0.0.1 --port 8000
```

This mode exposes the MCP server over HTTP.

Duta also implements OAuth-based authentication for remote MCP connectivity. Remote access requires appropriate client configuration, authentication, and network setup.

**Important:** Running an HTTP server does not automatically make it safe to expose to the public internet. Remote deployments require appropriate host validation, authentication, secure transport, and operational security measures.

## Security model

Filesystem access is designed around explicit authorization rather than unrestricted access.

Current protections include:

- Access requires configured permission rules.
- Operations are checked against their corresponding permissions.
- Path traversal attempts are rejected.
- Sensitive files and names are excluded by default.
- Sensitive-file exclusions cannot simply be overridden by granting ordinary access permissions.
- File creation does not overwrite existing files.
- Editing does not silently create missing files.
- File operations enforce configured content-size limits.

### Security limitations

Duta 0.1.0 is an initial usable foundation, not a formally audited security sandbox.

Filesystem permissions and operating-system state can change while a process is running. Application-level path validation cannot, by itself, eliminate every possible race condition or operating-system-level attack.

For stronger isolation:

- Run Duta under an unprivileged operating-system account.
- Restrict its workspace to the minimum necessary directories.
- Avoid exposing HTTP services publicly without appropriate security controls.
- Protect OAuth credentials and configuration.
- Use HTTPS for remote connections.
- Review the deployment environment before granting access to sensitive projects.

Duta does not execute arbitrary shell commands as part of its documented filesystem API.

## Current release: 0.1.0

Duta 0.1.0 establishes the initial reusable filesystem and integration foundation.

| Component | Status |
|---|---|
| Python filesystem core | Implemented |
| Permission-controlled discovery | Implemented |
| Authorized file reading | Implemented |
| Authorized file creation | Implemented |
| Authorized file editing | Implemented |
| Sensitive-file exclusions | Implemented |
| Command-line interface | Implemented |
| MCP stdio transport | Implemented |
| MCP Streamable HTTP transport | Implemented |
| OAuth-based remote MCP connectivity | Implemented; further hardening needed |
| Automated core tests | 13 passing tests |

The current test suite covers authorization, denied operations, file creation, editing, sensitive-file restrictions, content limits, and path traversal.

Passing these tests does not constitute a complete security audit or guarantee compatibility with every MCP client.

## Roadmap

Duta is intended to evolve beyond basic filesystem access.

Future development areas include:

- Improved integration with different AI applications and providers.
- Expanded security and permission controls.
- More comprehensive automated testing.
- Persistent and configurable remote authentication.
- A graphical management dashboard.
- Better visibility into filesystem activity and connected clients.

### Duta-X — Future development

Duta-X is a planned evolution of Duta focused on intelligent project context and continuity across AI systems.

Its proposed capabilities include:

- **Duta Context Engine:** Understands project state and relevant context.
- **Cross-LLM Continuity:** Preserves project continuity across different AI models.
- **Intelligent Context Retrieval:** Retrieves and compresses relevant project information.
- **Cross-Device Continuity:** Enables continuity across authorized devices.
- **Context Integrity:** Detects inconsistencies and contradictions in project context.
- **Comprehensive Logging Engine:** Maintains a structured history of relevant project and system events.

These are roadmap capabilities, not features claimed to be available in Duta 0.1.0.

## Contributing

Duta is intended to be a free and reusable project. Contributions, bug reports, security feedback, and integration ideas are welcome.

Before submitting changes:

1. Run the existing automated tests.
2. Add tests for new functionality.
3. Respect the permission model.
4. Avoid introducing unnecessary external dependencies.
5. Never commit credentials, private configuration, or personal project files.

## License

Duta is intended to be released under the MIT License. See the repository's `LICENSE` file for the applicable license terms.
