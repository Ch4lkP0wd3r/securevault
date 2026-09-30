# Lab: Build a Simple Password Vault

This project is a small password manager made for learning Python.
We will keep the code simple and focus on the core ideas:

- a vault file
- a master password
- saved login entries
- reading and deleting entries

## Lab 1: Create a vault

The first step is to make a vault file.

```bash
python -m securevault init
```

The program asks for a master password twice.
This password is the key that unlocks the vault.

Important:
- choose a password that is not too weak
- do not forget it
- if you forget it, the saved data is locked forever

## Lab 2: Add a password entry

Now add a login for a website.

```bash
python -m securevault add github alice MyPassword123
```

This saves:
- site: github
- username: alice
- password: MyPassword123

You can also add a note:

```bash
python -m securevault add gmail alice mypass123 -n "college email"
```

## Lab 3: List saved entries

To see everything saved in your vault:

```bash
python -m securevault list
```

You should see each site and username.

## Lab 4: Read one saved entry

To show one login:

```bash
python -m securevault get github
```

This prints the site, username, password, and notes.

## Lab 5: Delete one entry

If you no longer need a login:

```bash
python -m securevault delete github -y
```

The `-y` flag skips the confirmation question.

## Using a custom vault path

You can place the vault somewhere else:

```bash
python -m securevault --vault myvault.svlt init
```

## Project structure

```text
securevault-cli/
├── securevault/
│   ├── __main__.py
│   ├── cli.py
│   ├── strength.py
│   ├── vault.py
│   ├── storage.py
│   └── common_passwords.txt
├── tests/
│   └── test_securevault.py
├── README.md
└── .gitignore
```

## Run the tests

```bash
python -m unittest discover -s tests -v
```
Made By Dhairya Singh Dhaila
26BCY10031
VIT Bhopal University

## Academic Project Documentation

This repository contains the implementation and supporting documentation for the SecureVault academic project.

- [Project Statement](statement.md)
- [System Architecture](docs/architecture.md)
- [Workflow](docs/workflow.md)
- [Use Case Diagram](docs/use-case.md)
- [Class/Component Diagram](docs/class-diagram.md)
- [Sequence Diagram](docs/sequence-diagram.md)
- [Design Decisions](docs/design-decisions.md)
- [Testing](docs/testing.md)
- [Non-Functional Requirements](docs/non-functional-requirements.md)

> SecureVault is a local educational password-vault project. It should not be treated as a replacement for a professionally audited password manager.
