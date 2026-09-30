"""Command-line interface for the password manager."""

import argparse
import getpass
import os
import sys
from pathlib import Path

from . import __version__, storage, strength
from .vault import Vault, VaultError

DEFAULT_VAULT = Path.home() / ".securevault" / "vault.svlt"


class CLIError(Exception):
    pass


def build_parser():
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--vault",
        default=os.environ.get("SECUREVAULT_PATH", str(DEFAULT_VAULT)),
        help="path to the vault file",
    )

    parser = argparse.ArgumentParser(
        prog="securevault",
        description="Simple password manager",
    )
    parser.add_argument("--version", action="version", version="securevault %s" % __version__)
    sub = parser.add_subparsers(dest="command", required=True, metavar="command")

    p = sub.add_parser("init", parents=[common], help="create a new vault")
    p.add_argument("--allow-weak", action="store_true", help=argparse.SUPPRESS)

    p = sub.add_parser("add", parents=[common], help="save a login")
    p.add_argument("site")
    p.add_argument("username")
    p.add_argument("password", nargs="?")
    p.add_argument("-n", "--notes", default="")

    p = sub.add_parser("get", parents=[common], help="show one saved login")
    p.add_argument("site")
    p.add_argument("username", nargs="?")

    p = sub.add_parser("list", parents=[common], help="show saved entries")

    p = sub.add_parser("delete", parents=[common], help="remove a saved login")
    p.add_argument("site")
    p.add_argument("username", nargs="?")
    p.add_argument("-y", "--yes", action="store_true", help="skip confirmation")

    return parser


def _open_vault(path):
    if not storage.vault_exists(path):
        raise CLIError("No vault found at %s. Run 'init' first." % path)

    master = getpass.getpass("Master password: ")
    vault = Vault.from_dict(storage.load_vault(path, master))
    return vault, master


def _save(path, vault, master):
    storage.save_vault(path, vault.to_dict(), master)


def _prompt_new_password(label):
    password = getpass.getpass(label + ": ")
    if password == "":
        raise CLIError("Password cannot be empty.")
    return password


def cmd_init(args):
    if storage.vault_exists(args.vault):
        raise CLIError("A vault already exists at %s." % args.vault)

    master = getpass.getpass("Choose a master password: ")
    if len(master) < 8:
        raise CLIError("The master password must be at least 8 characters.")

    again = getpass.getpass("Repeat master password: ")
    if master != again:
        raise CLIError("The passwords did not match.")

    # The master password should be hard to guess.
    result = strength.check_strength(master)
    if result.rating == "Weak" and not args.allow_weak:
        print("Strength : %s  (score %s/8, about %s bits of entropy)" % (
            result.rating, result.score, int(result.entropy_bits)
        ))
        for tip in result.suggestions:
            print("  - %s" % tip)
        raise CLIError("That master password is too weak. Pick a stronger one.")

    empty_vault = Vault()
    storage.save_vault(args.vault, empty_vault.to_dict(), master)
    print("Vault created at %s" % args.vault)
    return 0


def cmd_add(args):
    vault, master = _open_vault(args.vault)

    if args.password is not None:
        password = args.password
    else:
        password = _prompt_new_password("Password for %s" % args.site)

    # Check duplicate entries before saving.
    vault.add(args.site, args.username, password, args.notes)
    _save(args.vault, vault, master)
    print("Saved '%s' / '%s'." % (args.site, args.username))
    return 0


def cmd_get(args):
    vault, _ = _open_vault(args.vault)
    entry = vault.get(args.site, args.username)
    print("Site     : %s" % entry.site)
    print("Username : %s" % entry.username)
    print("Password : %s" % entry.password)
    print("Notes    : %s" % (entry.notes or "-"))
    return 0


def cmd_list(args):
    vault, _ = _open_vault(args.vault)
    items = vault.list_entries()

    if not items:
        print("No entries found.")
        return 0

    print("SITE    USERNAME")
    for entry in items:
        print("%s    %s" % (entry.site, entry.username))
    return 0


def cmd_delete(args):
    vault, master = _open_vault(args.vault)
    entry = vault.get(args.site, args.username)

    if not args.yes:
        answer = input("Delete '%s' / '%s'? [y/N] " % (entry.site, entry.username))
        if answer.strip().lower() not in ("y", "yes"):
            print("Cancelled.")
            return 0

    vault.delete(entry.site, entry.username)
    _save(args.vault, vault, master)
    print("Entry deleted.")
    return 0


COMMANDS = {
    "init": cmd_init,
    "add": cmd_add,
    "get": cmd_get,
    "list": cmd_list,
    "delete": cmd_delete,
}


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return COMMANDS[args.command](args)
    except (VaultError, storage.StorageError, strength.PasswordGenerationError, CLIError) as exc:
        print("Error: %s" % exc, file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\nCancelled.", file=sys.stderr)
        return 130
