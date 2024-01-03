"""Helper functions for Passwordy."""

import argparse

from constants import PASSWORD_SPECIAL_CHARACTERS1, PASSWORD_SPECIAL_CHARACTERS2


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
        help=f"Use special characters for password generation including {PASSWORD_SPECIAL_CHARACTERS1}",
    )
    args.add_argument(
        "--password_special_characters2",
        action=argparse.BooleanOptionalAction,
        default=False,
        type=bool,
        help=f"Use special characters for password generation including {PASSWORD_SPECIAL_CHARACTERS2}",
    )
    args.add_argument(
        "--password_additional_characters",
        default="",
        type=str,
        help=(
            "Provide a string with characters for password generation. "
            "Using ' or \" is not allowed as it will open Pandora's Box of insane automation bugs."
        ),
    )

    return args.parse_args()
