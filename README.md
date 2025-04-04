# ControlAegis

**ControlAegis: A configuration-driven PowerShell module for managing Windows Firewall rules (port blocking/allowing) and the hosts file (domain blocking), featuring backup and rollback capabilities.**

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Configuration (`config.json`)](#configuration-configjson)
- [Usage](#usage)
  - [Importing the Module](#importing-the-module)
  - [Available Commands](#available-commands)
  - [Examples](#examples)
- [Rollback](#rollback)
- [Logging](#logging)
- [Technologies Used](#technologies-used)
- [Current Status](#current-status)
- [Known Issues and Limitations](#known-issues-and-limitations)
- [Contributing](#contributing)
- [License](#license)
- [Contact](#contact)

---

## Overview

ControlAegis is a PowerShell module designed for system administrators and security-conscious users to manage basic network access controls on Windows systems in a declarative and automated way. It uses a central JSON configuration file (`config.json`) to define the desired state for blocking specific network ports (via Windows Firewall) and domain names (via the system's hosts file). It also allows configuring exceptions (allow rules) and includes safety features like automated backups and rollback capabilities.

---

## Features

- **Configuration-Driven:** Define your network policy (blocks, exceptions) in a central `config.json` file.
- **Port Blocking:** Automatically creates Windows Firewall rules to block specified outgoing/incoming TCP and UDP ports.
- **Domain Blocking:** Adds entries to the system's `hosts` file to block access to specified domains by redirecting them to `0.0.0.0`.
- **Firewall Exceptions:** Configure "Allow" rules in Windows Firewall for specific ports, either generally (any remote IP) or for specific remote IPs.
- **State Synchronization:** Applies the configured state upon module import and attempts to maintain consistency.
- **Backup and Rollback:** Automatically backs up Firewall configuration (`.wfw`) and the hosts file before modifications. Allows reverting the last N changes made through the module.
- **Logging:** Logs operations, warnings, and errors to a file (configurable path).
- **PowerShell CLI:** Manage blocks and exceptions directly from the PowerShell console using intuitive commands.

---

## Prerequisites

- **Operating System:** Windows
- **PowerShell Version:** 5.1 or later
- **Administrator Privileges:** Required to modify firewall rules and the hosts file.

---

## Installation

1. **Download or Clone the Repository:**
   ```bash
   git clone https://github.com/victorvernier/Control-Aegis.git
   ```
   Alternatively, download the ZIP file and extract it.

2. **Ensure Directory Structure:**
   The following structure should be maintained:
   ```
   ControlAegis-main/
   ├── ControlAegis.psm1       # Main module file
   ├── config/
   │   └── config.json         # Configuration file
   ├── core/
   │   └── CoreFunctions.ps1   # Core utilities
   ├── modules/
   │   ├── cli/                # CLI implementation files (*.ps1)
   │   ├── config/             # Config handling/validation (*.ps1)
   │   ├── firewall/           # Firewall interaction (*.ps1)
   │   ├── hosts/              # Hosts file interaction (*.ps1)
   │   ├── log_analysis/       # Logging/Rotation logic (*.ps1)
   │   └── rollback/           # Rollback logic (*.ps1)
   ├── logs/                   # Default log directory (created automatically)
   └── temp/                   # Temporary files (created automatically)
       └── backup/             # Backup files (created automatically)
   ```

3. **Unblock Files (If Necessary):**
   If you downloaded a ZIP file, Windows might block the script files. Right-click the `.psm1` and `.ps1` files, go to Properties, and click "Unblock" if available. Alternatively, run:
   ```powershell
   Get-ChildItem -Path .\ -Recurse | Unblock-File
   ```

4. **Configure `config.json`:**
   Open the `config\config.json` file with a text editor and adjust the `bloqueio`, `excecoes`, and `logs` sections according to your desired policy before the first import.

---

## Configuration (`config.json`)

The module's behavior is controlled by `config\config.json`. Below are the key sections:

### `bloqueio` (Blocking Rules)
Defines what to block:
- **`portas_tcp`**: List of TCP ports to block (primarily outbound by default).
- **`portas_udp`**: List of UDP ports to block (primarily outbound by default).
- **`dominios_bloqueados`**: List of domain names to block by adding them to the hosts file (redirected to `0.0.0.0`).

### `excecoes` (Exceptions)
Defines firewall "Allow" rules:
- **`portas_tcp` / `portas_udp`**: Arrays of exception objects. Each object requires:
  - `porta`: Port number.
  - `protocolo`: Protocol ("TCP" or "UDP").
  - `direcao`: Direction ("inbound" or "outbound").
  - `tipo` (optional): `"geral"` for general exceptions or specific exceptions requiring `remoteip` or `dominio`.
  - `remoteip` (optional): Remote IP address for the exception.
  - `dominio` (optional): Domain-specific exceptions (tracked in config but not directly implemented as firewall rules).

- **`dominios_permitidos`**: Automatically populated with domains from domain-specific exceptions added via `Add-Exception`.

### `logs` (Logging)
Configures logging behavior:
- **`caminho_logs_local`**: Path for storing log files (relative or absolute). Defaults to `./logs`.
- **`log_rotation_strategy`**: `"size"` or `"time"` (current implementation uses `max_files` for cleanup).
- **`log_rotation_size`**: Maximum log file size in MB before rotation.
- **`log_rotation_max_files`**: Maximum number of log files to keep.

---

## Usage

### Importing the Module
Run the following in PowerShell (as Administrator):
```powershell
Import-Module .\ControlAegis.psm1 -Force
```

### Available Commands
- **Ports:**
  - `Add-BlockedPort`: Blocks a specific port.
  - `Remove-BlockedPort`: Unblocks a specific port.
  - `List-BlockedPorts`: Lists blocked ports.

- **Domains:**
  - `Add-BlockedDomain`: Blocks a domain.
  - `Remove-BlockedDomain`: Unblocks a domain.
  - `List-BlockedDomains`: Lists blocked domains.

- **Exceptions:**
  - `Add-Exception`: Adds a firewall "Allow" rule.
  - `Remove-Exception`: Removes an exception.
  - `List-Exceptions`: Lists configured exceptions.

- **Rollback:**
  - `Invoke-Rollback`: Reverts the last N changes.

---

## Rollback

ControlAegis automatically creates backups of the Windows Firewall configuration and the hosts file before applying changes. Use `Invoke-Rollback` to revert recent changes.

---

## Logging

Logs are stored in the directory specified in `config.json`. They include operations, warnings, and errors.

---

## Technologies Used

- PowerShell 5.1+
- `netsh advfirewall`
- Hosts file modification
- JSON for configuration

---

## Current Status

The module is in beta, functionally stable, but with some known limitations.

---

## Known Issues and Limitations

- **File Access Errors:** Antivirus or EDR software may interfere with file access.
- **Rollback State:** Rollback does not revert in-memory configuration or `config.json`.
- **`netsh` Dependency:** Relies on `netsh`, which may be less robust in some environments.

---

## Contributing

Contributions are welcome! Check the [issues page](https://github.com/victorvernier/Control-Aegis/issues) for more information.

---

## License

This project is licensed under the [MIT License](https://github.com/victorvernier/Control-Aegis/blob/main/LICENSE).

---

## Contact

For questions or suggestions, contact: **victorvernier@protonmail.com**
