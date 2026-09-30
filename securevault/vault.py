"""Vault manager."""

from datetime import datetime, timezone

from .strength import check_strength, load_common_passwords

MAX_FIELD = 200
MAX_NOTES = 1000


class VaultError(Exception):
    pass


class ValidationError(VaultError):
    pass


class EntryExistsError(VaultError):
    pass


class EntryNotFoundError(VaultError):
    pass


class AmbiguousEntryError(VaultError):
    pass


class Entry:
    def __init__(self, site, username, password, notes="", created="", updated=""):
        self.site = site
        self.username = username
        self.password = password
        self.notes = notes
        self.created = created
        self.updated = updated


def _now():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _clean(value, name, required=True):
    if not isinstance(value, str):
        raise ValidationError(name + " must be text.")

    value = value.strip()
    if required and value == "":
        raise ValidationError(name + " cannot be empty.")

    limit = MAX_NOTES if name == "Notes" else MAX_FIELD
    if len(value) > limit:
        raise ValidationError(name + " is too long.")

    for ch in value:
        if ord(ch) < 32:
            raise ValidationError(name + " contains invalid control characters.")

    return value


class Vault:
    def __init__(self, entries=None):
        if entries is None:
            self.entries = []
        else:
            self.entries = list(entries)

    def _same(self, entry, site, username):
        return entry.site.lower() == site.lower() and entry.username.lower() == username.lower()

    def _resolve(self, site, username=None):
        site = _clean(site, "Site")
        matches = []
        for item in self.entries:
            if item.site.lower() == site.lower():
                matches.append(item)

        if username is not None:
            name = username.strip()
            new_matches = []
            for item in matches:
                if item.username.lower() == name.lower():
                    new_matches.append(item)
            matches = new_matches

        if not matches:
            if username is None:
                raise EntryNotFoundError("No entry found for '%s'." % site)
            raise EntryNotFoundError("No entry found for '%s' / '%s'." % (site, username))

        if len(matches) > 1:
            names = []
            for item in matches:
                names.append(item.username)
            raise AmbiguousEntryError("'%s' has several accounts (%s). Please give a username." % (site, ", ".join(names)))

        return matches[0]

    def add(self, site, username, password, notes=""):
        site = _clean(site, "Site")
        username = _clean(username, "Username")
        password = _clean(password, "Password")
        notes = _clean(notes, "Notes", required=False)

        # Do not allow duplicate site + username pairs.
        for item in self.entries:
            if self._same(item, site, username):
                raise EntryExistsError(
                    "An entry for '%s' / '%s' already exists. Use 'update' to change it." % (site, username)
                )

        now = _now()
        entry = Entry(site, username, password, notes, now, now)
        self.entries.append(entry)
        return entry

    def get(self, site, username=None):
        return self._resolve(site, username)

    def update(self, site, username=None, new_username=None, password=None, notes=None):
        entry = self._resolve(site, username)

        if new_username is None and password is None and notes is None:
            raise ValidationError("Nothing to update. Give a new username, password or notes.")

        if new_username is not None:
            new_username = _clean(new_username, "Username")
            for item in self.entries:
                if item is not entry and self._same(item, entry.site, new_username):
                    raise EntryExistsError("'%s' / '%s' already exists." % (entry.site, new_username))
            entry.username = new_username

        if password is not None:
            entry.password = _clean(password, "Password")

        if notes is not None:
            entry.notes = _clean(notes, "Notes", required=False)

        entry.updated = _now()
        return entry

    def delete(self, site, username=None):
        entry = self._resolve(site, username)
        self.entries.remove(entry)
        return entry

    def list_entries(self, search=None):
        items = []
        if search is None:
            items = list(self.entries)
        else:
            term = search.lower()
            for entry in self.entries:
                site_name = entry.site.lower()
                user_name = entry.username.lower()
                if term in site_name or term in user_name:
                    items.append(entry)

        def sort_key(item):
            return (item.site.lower(), item.username.lower())

        items.sort(key=sort_key)
        return items

    def audit(self):
        common = load_common_passwords()
        weak = []
        reused = []
        groups = {}

        for entry in self.entries:
            if entry.password not in groups:
                groups[entry.password] = []
            groups[entry.password].append(entry)

            result = check_strength(entry.password, common)
            if result.rating == "Weak":
                weak.append((entry, result))

        for group in groups.values():
            if len(group) > 1:
                reused.append(group)

        return {"total": len(self.entries), "weak": weak, "reused": reused}

    def to_dict(self):
        data = {"version": 1, "entries": []}
        for entry in self.entries:
            item = {
                "site": entry.site,
                "username": entry.username,
                "password": entry.password,
                "notes": entry.notes,
                "created": entry.created,
                "updated": entry.updated,
            }
            data["entries"].append(item)
        return data

    @classmethod
    def from_dict(cls, data):
        try:
            entries = []
            for item in data["entries"]:
                entry = Entry(
                    item["site"],
                    item["username"],
                    item["password"],
                    item.get("notes", ""),
                    item.get("created", ""),
                    item.get("updated", ""),
                )
                entries.append(entry)
        except (KeyError, TypeError):
            raise VaultError("The vault data has an unexpected format.")
        return cls(entries)
