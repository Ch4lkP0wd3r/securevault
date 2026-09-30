# Process Workflow

```text
START
  |
  v
Launch SecureVault
  |
  v
Create/Open Vault
  |
  v
Authenticate with Master Password
  |
  +----------------------+
  |                      |
  v                      v
Valid                  Invalid
  |                      |
  v                      v
Main Menu             Error Message
  |                      |
  +----------+-----------+
             |
             v
   +-------------------------+
   | Choose Operation        |
   | Add / Get / List        |
   | Update / Delete         |
   | Generate / Strength     |
   | Audit / Exit            |
   +------------+------------+
                |
                v
         Validate Input
                |
                v
        Process Operation
                |
                v
        Save / Display Result
                |
                v
          Return to Menu
                |
                v
              EXIT
```

## Typical User Flow

1. Start the application.
2. Create a new vault or open an existing vault.
3. Provide the master password.
4. Select a vault or password-management operation.
5. Enter and validate the required information.
6. Perform the operation.
7. Display the result or an error message.
8. Return to the main menu until the user exits.
