#!/usr/bin/python3
"""Passwordy is a secure password and HEX key generator."""
import argparse
import hashlib
import json
import secrets
import string
import sys
from abc import ABC, abstractmethod
from functools import reduce
from typing import ClassVar

# Passwords with a length of 32 characters or less should not contain duplicate symbols in a row
# 'no character pair with two equal symbols'
PASSWORD_LENGTH_WITHOUT_REPETITION: int = 32

# Key descriptions
KEY_DESCRIPTIONS = {
    "hex_key_16": "AES128, MD5:",
    "hex_key_20": "OSPFv3 SHA1 authentication, SHA1:",
    "hex_key_24": "AES192:",
    "hex_key_28": "SHA2 with 224 bit:",
    "hex_key_32": "AES256, MACsec PSK CAK/key and CKN/name, SHA2 with 256 bit, SHA256:",
    "hex_key_48": "SHA2 with 384 bit:",
    "hex_key_64": "SHA2 with 512 bit:",
    "password_24": "OSPFv2 with MD5, BGP with MD5:",
}


def parse_arguments() -> argparse.ArgumentParser:
    """Parse arguments."""
    args = argparse.ArgumentParser(description="Secure password and HEX key generator.")
    args.add_argument(
        "--brief",
        action=argparse.BooleanOptionalAction,
        default=False,
        type=bool,
        help="Brief output.",
    )
    args.add_argument(
        "--hex_key",
        action=argparse.BooleanOptionalAction,
        default=False,
        type=bool,
        help="Generate HEX key.",
    )
    args.add_argument(
        "-j",
        "--json",
        action=argparse.BooleanOptionalAction,
        default=False,
        type=bool,
        help="Return keys as JSON.",
    )
    args.add_argument(
        "-l",
        "--length",
        default=16,
        type=int,
        help="Number of characters for passwords or the HEX key size in Byte: 1 Byte == 2 Symbols == 8 bit.",
    )
    args.add_argument(
        "-n",
        "--number_of_keys",
        type=int,
        default=16,
        help="Number of keys, default value is 16.",
    )
    args.add_argument(
        "--password",
        action=argparse.BooleanOptionalAction,
        default=False,
        type=bool,
        help="Generate passwords.",
    )
    args.add_argument(
        "--password_lower_ascii",
        action=argparse.BooleanOptionalAction,
        default=True,
        type=bool,
        help="Use lower ASCII letters for password generation.",
    )
    args.add_argument(
        "--password_upper_ascii",
        action=argparse.BooleanOptionalAction,
        default=True,
        type=bool,
        help="Use upper ASCII letters for password generation.",
    )
    args.add_argument(
        "--password_digits",
        action=argparse.BooleanOptionalAction,
        default=True,
        type=bool,
        help="Use digits for password generation.",
    )
    args.add_argument(
        "--password_special_characters1",
        action=argparse.BooleanOptionalAction,
        default=False,
        type=bool,
        help="Use special characters for password generation including .:,;+-=*#_<>()[]§~",
    )
    args.add_argument(
        "--password_special_characters2",
        action=argparse.BooleanOptionalAction,
        default=False,
        type=bool,
        help="Use special characters for password generation including !?$&",
    )

    return args.parse_args()


class Key(ABC):
    """Abstract class for Key."""

    @abstractmethod
    def __init__(self: "Key", length: int) -> None:
        """Initialize Key."""

    @abstractmethod
    def __str__(self: "Key") -> str:
        """Return Key as str."""

    @abstractmethod
    def verbose(self: "Key") -> None:
        """Return Key as str with verbose information."""


class HexKey(Key):
    """Define hexadecimal key."""

    def __init__(self: "HexKey", length: int) -> None:
        """Initialize HexKey."""
        self.hex_key_size_byte: int = length
        self.key_size_symbols: int = self.hex_key_size_byte * 2
        self.key_size_bit: int = self.hex_key_size_byte * 8
        self.key: str = secrets.token_hex(self.hex_key_size_byte)

    def __str__(self: "HexKey") -> str:
        """Return HexKey as str."""
        return f"{self.key}"

    def brief(self: "HexKey") -> str:
        """Return Key as str."""
        return self.__str__()

    def verbose(self: "HexKey") -> None:
        """Return Key as str with verbose information."""
        return f"HEX key {self.hex_key_size_byte} Byte, {self.key_size_symbols} symbols, {self.key_size_bit} bit: {self.key}"


class PasswordKey(Key):
    """Define passwords as key."""

    def _select_symbols(self: "PasswordKey") -> str:
        """Select the sysmbols to be used for the password generation."""
        selected_symbols: str = ""
        if args.password_lower_ascii:
            selected_symbols += string.ascii_lowercase
        if args.password_upper_ascii:
            selected_symbols += string.ascii_uppercase
        if args.password_digits:
            selected_symbols += string.digits
        if args.password_special_characters1:
            symbols: str = ".:,;+-=*#_<>()[]§~"
            selected_symbols += symbols
        if args.password_special_characters2:
            symbols: str = "!?$&"
            selected_symbols += symbols
        return selected_symbols

    def __init__(self: "PasswordKey", length: int) -> None:
        """Initialize PasswordKey."""
        self.key_size_length: int = length
        selected_symbols: str = self._select_symbols()
        # Generate a good password with at least 1 symbol out of each symbol group
        while True:
            self.key: str = "".join(secrets.choice(selected_symbols) for i in range(self.key_size_length))
            if args.password_lower_ascii and not any(symbol.islower() for symbol in self.key):
                continue
            if args.password_upper_ascii and not any(symbol.isupper() for symbol in self.key):
                continue
            if args.password_digits and not any(symbol.isdigit() for symbol in self.key):
                continue
            if args.password_special_characters1 and not any(symbol in selected_symbols for symbol in self.key):
                continue
            if args.password_special_characters2 and not any(symbol in selected_symbols for symbol in self.key):
                continue
            # Passwords for e.g. BGP should not start with a digit
            if self.key[0].isdigit():
                continue
            # Check for duplicate symbols in a row ('no character pair with two equal symbols')
            if self.key_size_length <= PASSWORD_LENGTH_WITHOUT_REPETITION and bool(
                reduce(lambda x, y: (x is not y) and x and y, self.key)
            ):
                continue
            # From here on the password is good
            # Provide all
            self.key_md5 = hashlib.md5(self.key.encode()).hexdigest()  # noqa: S324
            self.key_sha1 = hashlib.sha1(self.key.encode()).hexdigest()  # noqa: S324
            self.key_sha224 = hashlib.sha224(self.key.encode()).hexdigest()
            self.key_sha256 = hashlib.sha256(self.key.encode()).hexdigest()
            self.key_sha384 = hashlib.sha384(self.key.encode()).hexdigest()
            self.key_sha512 = hashlib.sha512(self.key.encode()).hexdigest()
            self.key_sha3_224 = hashlib.sha3_224(self.key.encode()).hexdigest()
            self.key_sha3_256 = hashlib.sha3_256(self.key.encode()).hexdigest()
            self.key_sha3_384 = hashlib.sha3_384(self.key.encode()).hexdigest()
            self.key_sha3_512 = hashlib.sha3_512(self.key.encode()).hexdigest()

            break

    def __str__(self: "PasswordKey") -> str:
        """Return PasswordKey as str."""
        return f"{self.key}"

    def brief(self: "PasswordKey") -> str:
        """Return PasswordKey as str."""
        return self.__str__()

    def verbose(self: "PasswordKey") -> None:
        """Return Key as str with verbose information."""
        return (
            f"Password {self.key_size_length} characters: {self.key}\n"
            f"MD5: {self.key_md5}\n"
            f"SHA1: {self.key_sha1}\n"
            f"SHA224: {self.key_sha224}\n"
            f"SHA256: {self.key_sha256}\n"
            f"SHA384: {self.key_sha384}\n"
            f"SHA512: {self.key_sha512}\n"
            f"SHA3_224: {self.key_sha3_224}\n"
            f"SHA3_256: {self.key_sha3_256}\n"
            f"SHA3_384: {self.key_sha3_384}\n"
            f"SHA3_512: {self.key_sha3_512}\n"
        )


class KeyRing:
    """Can hold several Keys in a dict."""

    key_types: ClassVar[dict] = {"hex_key": HexKey, "password": PasswordKey}

    def __init__(self: "KeyRing") -> None:
        """Initialize KeyRing."""
        self.keys: dict = {}

    def add_key(self: "KeyRing", key_type: str, length: int, number_of_keys: int = 4) -> None:
        """Add key to KeyRing."""
        for _ in range(number_of_keys):
            dict_key_name = key_type + "_" + str(length)
            if dict_key_name not in self.keys:
                self.keys[dict_key_name] = []
            self.keys[dict_key_name].append(self.key_types[key_type](length))

    def delete_key(self: "KeyRing", key: HexKey) -> None:
        """Delete key from KeyRing."""
        if key in self.keys[key.hex_key_size_byte]:
            self.keys[key.hex_key_size_byte].remove(key)

    def json(self: "KeyRing") -> dict:
        """Return keys as JSON."""
        return print(json.dumps(self.keys, default=lambda __o: __o.__dict__))

    def print_brief(self: "KeyRing") -> None:
        """Print Keys to CLI without additional information."""
        for key_name in self.keys:
            for key in self.keys[key_name]:
                print(key.brief())

    def print_verbose(self: "KeyRing") -> None:
        """Print Keys to CLI with verbose information."""
        for key_name in self.keys:
            if key_name in KEY_DESCRIPTIONS:
                print(KEY_DESCRIPTIONS[key_name])
            for key in self.keys[key_name]:
                print(key.verbose())
            print()


def example_key_ring(key_ring: KeyRing) -> KeyRing:
    """Create a HexKeyRing with example data."""
    key_ring.add_key(key_type="hex_key", length=4, number_of_keys=4)
    key_ring.add_key(key_type="hex_key", length=8, number_of_keys=4)
    key_ring.add_key(key_type="hex_key", length=12, number_of_keys=4)
    key_ring.add_key(key_type="hex_key", length=16, number_of_keys=4)
    key_ring.add_key(key_type="hex_key", length=20, number_of_keys=4)
    key_ring.add_key(key_type="hex_key", length=24, number_of_keys=4)
    key_ring.add_key(key_type="hex_key", length=28, number_of_keys=4)
    key_ring.add_key(key_type="hex_key", length=32, number_of_keys=4)
    key_ring.add_key(key_type="hex_key", length=48, number_of_keys=4)
    key_ring.add_key(key_type="hex_key", length=64, number_of_keys=4)

    key_ring.add_key(key_type="password", length=8, number_of_keys=1)
    key_ring.add_key(key_type="password", length=12, number_of_keys=1)
    key_ring.add_key(key_type="password", length=16, number_of_keys=1)
    key_ring.add_key(key_type="password", length=20, number_of_keys=1)
    key_ring.add_key(key_type="password", length=24, number_of_keys=1)
    key_ring.add_key(key_type="password", length=28, number_of_keys=1)
    key_ring.add_key(key_type="password", length=32, number_of_keys=1)
    return key_ring


if __name__ == "__main__":
    if sys.version_info < (3, 9):  # noqa: UP036
        print("Python 3.9 or higher is required.")
        sys.exit(1)

    args: argparse.ArgumentParser = parse_arguments()

    key_ring = KeyRing()

    if args.hex_key:
        key_ring.add_key(key_type="hex_key", length=args.length, number_of_keys=args.number_of_keys)
    if args.password:
        key_ring.add_key(key_type="password", length=args.length, number_of_keys=args.number_of_keys)
    # Generate keys as example
    if not args.hex_key and not args.password:
        key_ring = example_key_ring(key_ring)

    # generate JSON as output...
    if args.json:
        key_ring.json()
    # ...or print to CLI
    elif args.brief:
        key_ring.print_brief()
    else:
        key_ring.print_verbose()
    sys.exit(0)
