# Use Case Diagram

```text
                    +------------------+
                    |      User        |
                    +--------+---------+
                             |
          +------------------+------------------+
          |                  |                  |
          v                  v                  v
   [Create/Open]      [Manage Credentials] [Password Tools]
          |                  |                  |
          |          +-------+-------+      +----+------+
          |          |       |       |      |           |
          |        [Add]   [Get] [List] [Generate] [Strength]
          |          |       |       |
          |        [Update] [Delete] |
          |                  |       |
          +------------------+-------+
                             |
                             v
                       [Security Audit]
```

## Actors and Use Cases

**Actor:** User

**Use cases:**
- Create/open vault
- Authenticate with master password
- Add credential
- Retrieve credential
- List credentials
- Update credential
- Delete credential
- Generate password
- Check password strength
- Audit password reuse
- Exit application
