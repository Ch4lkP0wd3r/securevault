# SecureVault — Project Statement

## 1. Problem Statement

Passwords are commonly reused, stored insecurely, or managed without adequate protection. This project addresses the problem of securely storing and managing website credentials through a Python-based command-line password vault.

SecureVault provides a local vault in which users can add, retrieve, list, update, and delete credentials while protecting stored vault data through encryption. The application also provides password generation, password-strength assessment, and password-reuse auditing features.

## 2. Scope

The project covers local password-vault management through a command-line interface.

### In Scope
- Creating and opening a password vault
- Adding, retrieving, listing, updating, and deleting credentials
- Encrypted local storage
- Master-password-based vault access
- Password generation
- Password-strength evaluation
- Password-reuse auditing
- Input validation and error handling
- Automated testing

### Out of Scope
- Cloud synchronization
- Multi-user account management
- Browser-extension integration
- Remote password sharing
- Recovery of a forgotten master password

## 3. Target Users

The intended users are individuals who need a simple local tool for organizing and protecting website credentials while learning and applying Python programming and software-development concepts.

## 4. High-Level Features

1. **Vault Management** — Create and access a password vault using a master password.
2. **Credential Management** — Add, view, list, update, and delete stored credentials.
3. **Secure Storage** — Protect vault data using encryption and integrity checks.
4. **Password Tools** — Generate passwords and evaluate password strength.
5. **Security Auditing** — Detect password reuse within stored credentials.
6. **Validation and Error Handling** — Handle invalid input and incorrect operations safely.
7. **Testing** — Verify core functionality through automated tests.
