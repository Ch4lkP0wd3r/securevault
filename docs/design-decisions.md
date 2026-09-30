# Design Decisions & Rationale

## Modular Design

SecureVault separates command-line interaction from application logic and storage. This makes the code easier to understand, test, and maintain.

## Local Storage

The project uses local storage so that the application can operate without requiring a remote service or database server.

## Encryption and Integrity

Credential data requires protection against ordinary plaintext exposure and unauthorized modification. SecureVault therefore uses protected vault storage rather than saving credentials directly in readable form.

## Password Utilities

Password generation and strength analysis are kept as separate functionality so users can create stronger credentials and assess existing ones.

## Validation and Errors

Input validation and explicit error handling reduce unexpected program failures and provide clearer feedback during incorrect operations.

## Testing

Automated tests are included to verify security-sensitive and functional behavior, including vault operations and invalid-input scenarios.
