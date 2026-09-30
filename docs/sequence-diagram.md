# Sequence Diagram — Add Credential

```text
User          CLI          Vault        Validation       Storage
 |             |             |              |              |
 |--add------->|             |              |              |
 |             |--request--->|              |              |
 |             |             |--validate--->|              |
 |             |             |<--valid-------|              |
 |             |             |----------------------------->|
 |             |             |          save encrypted data |
 |             |             |<-----------------------------|
 |             |<--success---|              |              |
 |<--result----|             |              |              |
```

## Sequence

1. The user selects the add-credential operation.
2. The CLI collects the required fields.
3. The vault logic validates the operation and input.
4. The credential is passed to the storage layer.
5. Storage persists the protected vault data.
6. The CLI reports success or an appropriate error.
