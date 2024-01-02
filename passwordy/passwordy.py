#!/usr/bin/python3
"""Passwordy is a secure password and HEX key generator."""
import argparse
import sys

from helpers import parse_arguments
from keyring import KeyRing


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
        key_ring.add_key(
            key_type="password",
            length=args.length,
            number_of_keys=args.number_of_keys,
            password_lower_ascii=args.password_lower_ascii,
            password_upper_ascii=args.password_upper_ascii,
            password_digits=args.password_digits,
            password_special_characters1=args.password_special_characters1,
            password_special_characters2=args.password_special_characters2,
            password_additional_characters=args.password_additional_characters,
        )
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
