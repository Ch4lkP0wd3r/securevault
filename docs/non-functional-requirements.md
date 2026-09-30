# Non-Functional Requirements

## 1. Security

Vault contents should not be stored as ordinary plaintext credentials. Authentication, encryption, integrity protection, and secure handling of vault data are core project concerns.

## 2. Usability

The application should provide a clear command-line workflow with understandable commands and error messages.

## 3. Reliability

Invalid operations, malformed input, duplicate entries, and authentication failures should be handled without unexpectedly terminating normal program execution.

## 4. Maintainability

The implementation is divided into focused modules so that vault logic, storage, password utilities, CLI behavior, and testing can be maintained independently.

## 5. Performance

Normal vault operations should complete quickly for a typical personal collection of credentials.

## 6. Resource Efficiency

The application is designed as a local command-line program and avoids requiring a continuously running server or database service.
