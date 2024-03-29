#!/usr/bin/python3
"""Passwordy is a secure password and HEX key generator."""
import argparse
import sys

from helpers import get_password, parse_arguments
from keyring import KeyRing


def example_key_ring(key_ring: KeyRing, args: argparse.ArgumentParser) -> KeyRing:
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
        show_plaintext_password=True,
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
        show_plaintext_password=True,
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
        show_plaintext_password=True,
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
        show_plaintext_password=True,
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
        show_plaintext_password=True,
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
        show_plaintext_password=True,
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
        show_plaintext_password=True,
    )
    return key_ring


def main() -> None:
    """Execute main function."""
    args: argparse.ArgumentParser = parse_arguments()

    password_plaintext: str = ""
    if args.input_prompt:
        # Get password from user input
        password_plaintext = get_password()

    # Create a KeyRing object to store keys
    key_ring = KeyRing()

    if args.hex_key:
        key_ring.add_key(key_type="hex_key", length=args.length, number_of_keys=args.number_of_keys)
    if args.password:
        key_ring.add_key(
            key_type="password",
            length=args.length,
            number_of_keys=args.number_of_keys,
            password_plaintext=password_plaintext,
            password_lower_ascii=args.password_lower_ascii,
            password_upper_ascii=args.password_upper_ascii,
            password_digits=args.password_digits,
            password_special_characters1=args.password_special_characters1,
            password_special_characters2=args.password_special_characters2,
            password_additional_characters=args.password_additional_characters,
            allow_all_characters=args.allow_all_characters,
            show_plaintext_password=args.show_plaintext_password,
        )
    # Generate example keys
    if not args.hex_key and not args.password:
        key_ring = example_key_ring(key_ring, args)

    # generate JSON as output...
    if args.json:
        key_ring.json()
    # ...or print to CLI
    elif args.brief:
        key_ring.print_brief()
    else:
        key_ring.print_verbose()


if __name__ == "__main__":
    if sys.version_info < (3, 9):  # noqa: UP036
        print("Python 3.9 or higher is required.")  # noqa: T201
        sys.exit(1)

    main()
    sys.exit(0)
