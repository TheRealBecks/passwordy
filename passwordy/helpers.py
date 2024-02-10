"""Helper functions for Passwordy."""

import argparse
from getpass import getpass

from constants import PASSWORD_FORBIDDEN_CHARACTERS, PASSWORD_SPECIAL_CHARACTERS1, PASSWORD_SPECIAL_CHARACTERS2


def get_password() -> str:
    """Get password from user input."""
    return getpass()


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
        "--hex-key",
        action=argparse.BooleanOptionalAction,
        default=False,
        type=bool,
        help="Generate HEX key.",
    )
    args.add_argument(
        "-i",
        "--input-prompt",
        action=argparse.BooleanOptionalAction,
        default=False,
        type=bool,
        help="Provide your existing password in a secure prompt.",
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
        "--number-of-keys",
        type=int,
        default=1,
        help="Number of keys, default value is 1.",
    )
    args.add_argument(
        "--password",
        action=argparse.BooleanOptionalAction,
        default=False,
        type=bool,
        help="Generate passwords.",
    )
    args.add_argument(
        "--password-lower-ascii",
        action=argparse.BooleanOptionalAction,
        default=True,
        type=bool,
        help="Use lower ASCII letters for password generation.",
    )
    args.add_argument(
        "--password-upper-ascii",
        action=argparse.BooleanOptionalAction,
        default=True,
        type=bool,
        help="Use upper ASCII letters for password generation.",
    )
    args.add_argument(
        "--password-digits",
        action=argparse.BooleanOptionalAction,
        default=True,
        type=bool,
        help="Use digits for password generation.",
    )
    args.add_argument(
        "--password-special-characters1",
        action=argparse.BooleanOptionalAction,
        default=False,
        type=bool,
        help=f"Use special characters for password generation including {PASSWORD_SPECIAL_CHARACTERS1}",
    )
    args.add_argument(
        "--password-special-characters2",
        action=argparse.BooleanOptionalAction,
        default=False,
        type=bool,
        help=f"Use special characters for password generation including {PASSWORD_SPECIAL_CHARACTERS2}",
    )
    args.add_argument(
        "--password-additional-characters",
        default="",
        type=str,
        help=(
            "Provide a string with characters for password generation. "
            "Using ' or \" is not allowed as it will open Pandora's Box of insane automation bugs."
        ),
    )
    args.add_argument(
        "-s",
        "--secure",
        action=argparse.BooleanOptionalAction,
        default=False,
        type=bool,
        help=(
            "Secure passwords: Shortcut for "
            "--password-lower-ascii, "
            "--password-upper-ascii, "
            "--password-digits, "
            "--password-special-characters1, "
            "--password-special-characters2, "
        ),
    )
    args.add_argument(
        "--show-plaintext-password",
        action=argparse.BooleanOptionalAction,
        default=False,
        type=bool,
        help="Show plaintext password in output.",
    )
    args.add_argument(
        "--allow-all-characters",
        action=argparse.BooleanOptionalAction,
        default=False,
        type=bool,
        help=(
            "Not recommended: Allow all characters for password generation: "
            f"{PASSWORD_FORBIDDEN_CHARACTERS} (and whitespace)."
        ),
    )

    parsed_args = args.parse_args()

    # Enabling the password generation will disable the HEX key generation if not explicitely enabled with --hex-key
    if parsed_args.input_prompt and not parsed_args.password:
        parsed_args.password = True
    # No other output than JSON allowed
    if parsed_args.json:
        parsed_args.brief = False
    # Overwrite password symbols if --secure is used
    if parsed_args.secure:
        parsed_args.password_lower_ascii = True
        parsed_args.password_upper_ascii = True
        parsed_args.password_digits = True
        parsed_args.password_special_characters1 = True
        parsed_args.password_special_characters2 = True

    return parsed_args
