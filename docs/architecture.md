# System Architecture

SecureVault follows a modular Python architecture.

```text
+----------------------+
|    Command Line UI   |
|        cli.py        |
+----------+-----------+
           |
           v
+----------------------+       +----------------------+
|   Vault Management  |------>| Password Tools       |
|      vault.py       |       | strength.py          |
+----------+-----------+       +----------------------+
           |
           v
+----------------------+
| Secure Storage       |
| storage.py           |
+----------+-----------+
           |
           v
+----------------------+
| Local Encrypted Vault|
| Vault data file      |
+----------------------+

Supporting modules:
- Validation / error handling
- Data models / serialization
- Automated tests
```

## Components

| Component | Responsibility |
|---|---|
| CLI | Accepts commands and displays results |
| Vault | Coordinates credential operations |
| Storage | Handles persistent protected vault data |
| Password tools | Generates and evaluates passwords |
| Validation/error handling | Rejects invalid operations safely |
| Tests | Verifies expected behavior |

The architecture separates user interaction, application logic, password utilities, and storage so individual components can be maintained and tested independently.
