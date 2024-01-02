#!/usr/bin/python3
"""Passwordy is a secure password and HEX key generator."""
import argparse
import json
import sys
from typing import ClassVar

from constants import KEY_DESCRIPTIONS
from helpers import parse_arguments
from keys import HexKey, Key, PasswordKey


class KeyRing:
    """Can hold several Keys in a dict."""

    key_types: ClassVar[dict] = {"hex_key": HexKey, "password": PasswordKey}

    def __init__(self: "KeyRing") -> None:
        """Initialize KeyRing."""
        self.keys: dict = {}

    def add_key(self: "KeyRing", key_type: str, length: int, number_of_keys: int = 4, **kwargs: any) -> None:
        """Add key to KeyRing."""
        for _ in range(number_of_keys):
            dict_key_name = key_type + "_" + str(length)
            if dict_key_name not in self.keys:
                self.keys[dict_key_name] = []
            self.keys[dict_key_name].append(self.key_types[key_type](length=length, **kwargs))

    def delete_key(self: "KeyRing", key: Key) -> None:
        """Delete key from KeyRing."""
        if key in self.keys[key.hex_key_size_byte]:
            self.keys[key.hex_key_size_byte].remove(key)

    def json(self: "KeyRing") -> dict:
        """Return keys as JSON."""
        return print(json.dumps(self.keys, default=lambda __o: __o.__dict__))  # noqa: T201

    def print_brief(self: "KeyRing") -> None:
        """Print keys to CLI without additional information."""
        for key_name in self.keys:
            for key in self.keys[key_name]:
                print(key.brief())  # noqa: T201

    def print_verbose(self: "KeyRing") -> None:
        """Print keys to CLI with verbose information."""
        for key_name in self.keys:
            if key_name in KEY_DESCRIPTIONS:
                print(KEY_DESCRIPTIONS[key_name])  # noqa: T201
            for key in self.keys[key_name]:
                print(key.verbose())  # noqa: T201
            print()  # noqa: T201


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

    key_ring.add_key(
        key_type="password",
        length=8,
        number_of_keys=1,
        password_lower_ascii=args.password_lower_ascii,
        password_upper_ascii=args.password_upper_ascii,
        password_digits=args.password_digits,
        password_special_characters1=args.password_special_characters1,
        password_special_characters2=args.password_special_characters2,
        password_additional_characters=args.password_additional_characters,
    )
    key_ring.add_key(
        key_type="password",
        length=12,
        number_of_keys=1,
        password_lower_ascii=args.password_lower_ascii,
        password_upper_ascii=args.password_upper_ascii,
        password_digits=args.password_digits,
        password_special_characters1=args.password_special_characters1,
        password_special_characters2=args.password_special_characters2,
        password_additional_characters=args.password_additional_characters,
    )
    key_ring.add_key(
        key_type="password",
        length=16,
        number_of_keys=1,
        password_lower_ascii=args.password_lower_ascii,
        password_upper_ascii=args.password_upper_ascii,
        password_digits=args.password_digits,
        password_special_characters1=args.password_special_characters1,
        password_special_characters2=args.password_special_characters2,
        password_additional_characters=args.password_additional_characters,
    )
    key_ring.add_key(
        key_type="password",
        length=20,
        number_of_keys=1,
        password_lower_ascii=args.password_lower_ascii,
        password_upper_ascii=args.password_upper_ascii,
        password_digits=args.password_digits,
        password_special_characters1=args.password_special_characters1,
        password_special_characters2=args.password_special_characters2,
        password_additional_characters=args.password_additional_characters,
    )
    key_ring.add_key(
        key_type="password",
        length=24,
        number_of_keys=1,
        password_lower_ascii=args.password_lower_ascii,
        password_upper_ascii=args.password_upper_ascii,
        password_digits=args.password_digits,
        password_special_characters1=args.password_special_characters1,
        password_special_characters2=args.password_special_characters2,
        password_additional_characters=args.password_additional_characters,
    )
    key_ring.add_key(
        key_type="password",
        length=28,
        number_of_keys=1,
        password_lower_ascii=args.password_lower_ascii,
        password_upper_ascii=args.password_upper_ascii,
        password_digits=args.password_digits,
        password_special_characters1=args.password_special_characters1,
        password_special_characters2=args.password_special_characters2,
        password_additional_characters=args.password_additional_characters,
    )
    key_ring.add_key(
        key_type="password",
        length=32,
        number_of_keys=1,
        password_lower_ascii=args.password_lower_ascii,
        password_upper_ascii=args.password_upper_ascii,
        password_digits=args.password_digits,
        password_special_characters1=args.password_special_characters1,
        password_special_characters2=args.password_special_characters2,
        password_additional_characters=args.password_additional_characters,
    )
    return key_ring


if __name__ == "__main__":
    if sys.version_info < (3, 9):  # noqa: UP036
        print("Python 3.9 or higher is required.")  # noqa: T201
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
