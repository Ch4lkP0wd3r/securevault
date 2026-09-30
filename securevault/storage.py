"""File storage and encryption."""

import hashlib
import hmac
import json
import os
import secrets
import tempfile

MAGIC = b"SVLT1"
SALT_LEN = 16
NONCE_LEN = 16
TAG_LEN = 32
BLOCK = 32
DEFAULT_ITERATIONS = 200000
MAX_ITERATIONS = 5000000
HEADER_LEN = len(MAGIC) + 4 + SALT_LEN + NONCE_LEN


class StorageError(Exception):
    pass


class WrongPasswordError(StorageError):
    pass


class CorruptFileError(StorageError):
    pass


def derive_keys(password, salt, iterations):
    material = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        iterations,
        dklen=64,
    )
    return material[:32], material[32:]


def _xor_keystream(key, nonce, data):
    out = bytearray()
    block_no = 0
    start = 0

    while start < len(data):
        stream = hmac.new(key, nonce + block_no.to_bytes(8, "big"), hashlib.sha256).digest()
        count = 0
        while count < BLOCK and start + count < len(data):
            out.append(data[start + count] ^ stream[count])
            count += 1
        start += count
        block_no += 1

    return bytes(out)


def encrypt_bytes(plain_text, password, iterations=DEFAULT_ITERATIONS):
    salt = secrets.token_bytes(SALT_LEN)
    nonce = secrets.token_bytes(NONCE_LEN)
    enc_key, mac_key = derive_keys(password, salt, iterations)
    header = MAGIC + iterations.to_bytes(4, "big") + salt + nonce
    cipher_text = _xor_keystream(enc_key, nonce, plain_text)
    tag = hmac.new(mac_key, header + cipher_text, hashlib.sha256).digest()
    return header + cipher_text + tag


def decrypt_bytes(blob, password):
    if len(blob) < HEADER_LEN + TAG_LEN or not blob.startswith(MAGIC):
        raise CorruptFileError("This is not a valid SecureVault file.")

    pos = len(MAGIC)
    iterations = int.from_bytes(blob[pos:pos + 4], "big")
    pos += 4
    salt = blob[pos:pos + SALT_LEN]
    pos += SALT_LEN
    nonce = blob[pos:pos + NONCE_LEN]

    if iterations < 1 or iterations > MAX_ITERATIONS:
        raise CorruptFileError("The vault file header is damaged.")

    enc_key, mac_key = derive_keys(password, salt, iterations)
    expected = hmac.new(mac_key, blob[:-TAG_LEN], hashlib.sha256).digest()
    if not hmac.compare_digest(expected, blob[-TAG_LEN:]):
        raise WrongPasswordError("Wrong master password (or the vault file has been modified).")

    return _xor_keystream(enc_key, nonce, blob[HEADER_LEN:-TAG_LEN])


def vault_exists(path):
    return os.path.isfile(path)


def save_vault(path, data, password):
    blob = encrypt_bytes(json.dumps(data).encode("utf-8"), password)
    directory = os.path.dirname(os.path.abspath(path))
    temp_path = None

    try:
        os.makedirs(directory, exist_ok=True)
        fd, temp_path = tempfile.mkstemp(dir=directory, prefix=".svlt-")
        with os.fdopen(fd, "wb") as handle:
            handle.write(blob)
        os.chmod(temp_path, 0o600)
        os.replace(temp_path, path)
    except OSError as exc:
        if temp_path and os.path.exists(temp_path):
            os.unlink(temp_path)
        raise StorageError("Could not write the vault file: %s" % exc) from exc


def load_vault(path, password):
    try:
        with open(path, "rb") as handle:
            blob = handle.read()
    except FileNotFoundError:
        raise StorageError("No vault found at %s. Run 'init' first." % path) from None
    except OSError as exc:
        raise StorageError("Could not read the vault file: %s" % exc) from exc

    plain_text = decrypt_bytes(blob, password)
    try:
        text = plain_text.decode("utf-8")
        return json.loads(text)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CorruptFileError("The vault contents are damaged.") from exc
