"""
Define Key types.

HexKey: Hexadecimal key
PasswordKey: Password key
"""

import hashlib
import secrets
import string
import subprocess
from abc import ABC, abstractmethod
from functools import reduce

from constants import (
    PASSWORD_LENGTH_WITHOUT_REPETITION,
    PASSWORD_SPECIAL_CHARACTERS1,
    PASSWORD_SPECIAL_CHARACTERS2,
    SALT_ADDITIONAL_CHARACTERS,
    SALT_LENGTH,
)


class Key(ABC):
    """Abstract class for Key."""

    @abstractmethod
    def __init__(self: "Key", length: int) -> None:
        """Initialize Key."""

    @abstractmethod
    def __str__(self: "Key") -> str:
        """Return Key as str."""

    @abstractmethod
    def brief(self: "Key") -> str:
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
        """Return HexKey as str."""
        return self.__str__()

    def verbose(self: "HexKey") -> str:
        """Return HexKey as str with verbose information."""
        return (
            f"HEX key {self.hex_key_size_byte} Byte,"
            f" {self.key_size_symbols} symbols,"
            f" {self.key_size_bit} bit:"
            f" {self.key}"
        )


class PasswordKey(Key):
    """Define passwords as key."""

    def _password_strength(  # noqa: PLR0913
        self: "PasswordKey",
        *,
        lower_ascii: bool = False,
        upper_ascii: bool = False,
        digits: bool = False,
        special_characters1: bool = False,
        special_characters2: bool = False,
        additional_characters: str = "",
    ) -> dict:
        """Define the password strength to be used for the password generation."""
        password_strength: dict = {}
        password_strength["lower_ascii"] = lower_ascii
        password_strength["upper_ascii"] = upper_ascii
        password_strength["digits"] = digits
        password_strength["special_characters1"] = special_characters1
        password_strength["special_characters2"] = special_characters2
        password_strength["additional_characters"] = bool(additional_characters)

        selected_symbols: str = ""
        if lower_ascii:
            selected_symbols += string.ascii_lowercase
        if upper_ascii:
            selected_symbols += string.ascii_uppercase
        if digits:
            selected_symbols += string.digits
        if special_characters1:
            selected_symbols += PASSWORD_SPECIAL_CHARACTERS1
        if special_characters2:
            selected_symbols += PASSWORD_SPECIAL_CHARACTERS2
        if additional_characters != "":
            selected_symbols += additional_characters
        password_strength["selected_symbols"] = selected_symbols

        return password_strength

    def _generate_password(
        self: "PasswordKey",
        *,
        key_size_length: int,
        password_strength: dict,
        check_password_strength: bool = True,
        check_starting_with_digit: bool = True,
    ) -> str:
        """Generate a good password with optionally at least 1 symbol out of each defined symbol group."""
        while True:
            key: str = "".join(secrets.choice(password_strength["selected_symbols"]) for _ in range(key_size_length))
            if (
                check_password_strength
                and password_strength["lower_ascii"]
                and not any(symbol.islower() for symbol in key)
            ):
                continue
            if (
                check_password_strength
                and password_strength["upper_ascii"]
                and not any(symbol.isupper() for symbol in key)
            ):
                continue
            if check_password_strength and password_strength["digits"] and not any(symbol.isdigit() for symbol in key):
                continue
            if (
                check_password_strength
                and password_strength["special_characters1"]
                and not any(symbol in PASSWORD_SPECIAL_CHARACTERS1 for symbol in key)
            ):
                continue
            if (
                check_password_strength
                and password_strength["special_characters2"]
                and not any(symbol in PASSWORD_SPECIAL_CHARACTERS2 for symbol in key)
            ):
                continue
            # Passwords for e.g. BGP must not start with a digit
            if check_starting_with_digit and key[0].isdigit():
                continue
            # Check for duplicate symbols in a row ('no character pair with two equal symbols')
            if key_size_length <= PASSWORD_LENGTH_WITHOUT_REPETITION and not bool(
                reduce(lambda x, y: (x is not y) and x and y, key)
            ):
                continue
            # From here on the key is good
            break
        return key

    def _generate_unsalted_hashes(self: "PasswordKey") -> None:
        """Provide all kind of unsalted hashes for the password."""
        self.key_md5 = hashlib.md5(self.key.encode(encoding="UTF-8")).hexdigest()  # noqa: S324
        self.key_sha1 = hashlib.sha1(self.key.encode(encoding="UTF-8")).hexdigest()  # noqa: S324
        self.key_sha224 = hashlib.sha224(self.key.encode(encoding="UTF-8")).hexdigest()
        self.key_sha256 = hashlib.sha256(self.key.encode(encoding="UTF-8")).hexdigest()
        self.key_sha384 = hashlib.sha384(self.key.encode(encoding="UTF-8")).hexdigest()
        self.key_sha512 = hashlib.sha512(self.key.encode(encoding="UTF-8")).hexdigest()
        self.key_sha3_224 = hashlib.sha3_224(self.key.encode(encoding="UTF-8")).hexdigest()
        self.key_sha3_256 = hashlib.sha3_256(self.key.encode(encoding="UTF-8")).hexdigest()
        self.key_sha3_384 = hashlib.sha3_384(self.key.encode(encoding="UTF-8")).hexdigest()
        self.key_sha3_512 = hashlib.sha3_512(self.key.encode(encoding="UTF-8")).hexdigest()

    def _run_openssl(self: "PasswordKey", salt: str, openssl_type: str) -> subprocess.CompletedProcess:
        """Run openssl to generate service keys."""
        try:
            openssl_result = subprocess.run(
                ["openssl", "passwd", f"-{openssl_type}", "-salt", f"{salt}", f"'{self.key}'"],  # noqa: S603, S607
                capture_output=True,
                check=True,
                text=True,
            )
            return openssl_result.stdout.strip() if openssl_result.returncode == 0 else ""
        # TODO @TheRealBecks: Check if empty string as return is a good idea
        except FileNotFoundError:
            return ""
        except PermissionError:
            return ""

    def _generate_salted_hash(self: "PasswordKey", hash_type: str) -> str:
        """Generate a salted hash."""
        hash_types: dict = {
            "apr1": {
                "openssl_type": "apr1",
                "salt_length": 8,
                "salt_additional_characters": "",
            },
            "md5": {
                "openssl_type": "1",
                "salt_length": 8,
                "salt_additional_characters": "",
            },
            "md5_cisco_ios": {
                "openssl_type": "1",
                "salt_length": 4,
                "salt_additional_characters": "",
            },
            "sha256": {
                "openssl_type": "5",
                "salt_length": SALT_LENGTH,
                "salt_additional_characters": SALT_ADDITIONAL_CHARACTERS,
            },
            "sha512": {
                "openssl_type": "6",
                "salt_length": SALT_LENGTH,
                "salt_additional_characters": SALT_ADDITIONAL_CHARACTERS,
            },
        }

        salt_strength = self._password_strength(
            lower_ascii=True,
            upper_ascii=True,
            digits=True,
            special_characters1=False,
            special_characters2=False,
            additional_characters=hash_types[hash_type]["salt_additional_characters"],
        )
        salt = self._generate_password(
            key_size_length=hash_types[hash_type]["salt_length"],
            password_strength=salt_strength,
            check_password_strength=False,
            check_starting_with_digit=False,
        )
        return self._run_openssl(salt=salt, openssl_type=hash_types[hash_type]["openssl_type"])

    def _generate_salted_hashes(self: "PasswordKey") -> None:
        """Provide all kind of salted hashes for the password."""
        self.key_md5_salted = self._generate_salted_hash(hash_type="md5")
        self.key_md5_salted_cisco_ios = self._generate_salted_hash(hash_type="md5_cisco_ios")
        self.key_sha256_salted = self._generate_salted_hash(hash_type="sha256")
        self.key_sha512_salted = self._generate_salted_hash(hash_type="sha512")
        self.key_apr1_salted = self._generate_salted_hash(hash_type="apr1")

    def __init__(  # noqa: PLR0913
        self: "PasswordKey",
        length: int,
        *,
        password_lower_ascii: bool = True,
        password_upper_ascii: bool = True,
        password_digits: bool = True,
        password_special_characters1: bool = False,
        password_special_characters2: bool = False,
        password_additional_characters: str = "",
    ) -> None:
        """Initialize PasswordKey."""
        self.key_size_length: int = length
        password_strength = self._password_strength(
            lower_ascii=password_lower_ascii,
            upper_ascii=password_upper_ascii,
            digits=password_digits,
            special_characters1=password_special_characters1,
            special_characters2=password_special_characters2,
            additional_characters=password_additional_characters,
        )
        self.key = self._generate_password(key_size_length=self.key_size_length, password_strength=password_strength)
        self._generate_unsalted_hashes()
        self._generate_salted_hashes()

    def __str__(self: "PasswordKey") -> str:
        """Return PasswordKey as str."""
        return f"{self.key}"

    def brief(self: "PasswordKey") -> str:
        """Return PasswordKey as str."""
        return self.__str__()

    def verbose(self: "PasswordKey") -> str:
        """Return PasswordKey as str with verbose information."""
        return (
            f"key (plaintext password) with {self.key_size_length} characters: {self.key}\n"
            f"key_md5: {self.key_md5}\n"
            f"key_sha1: {self.key_sha1}\n"
            f"key_sha224: {self.key_sha224}\n"
            f"key_sha256: {self.key_sha256}\n"
            f"key_sha384: {self.key_sha384}\n"
            f"key_sha512: {self.key_sha512}\n"
            f"key_sha3_224: {self.key_sha3_224}\n"
            f"key_sha3_256: {self.key_sha3_256}\n"
            f"key_sha3_384: {self.key_sha3_384}\n"
            f"key_sha3_512: {self.key_sha3_512}\n"
            f"key_md5_salted: {self.key_md5_salted}\n"
            f"key_md5_salted_cisco_ios (e.g. Cisco IOS): {self.key_md5_salted_cisco_ios}\n"
            f"key_sha256_salted (e.g. Cisco NX-OS): {self.key_sha256_salted}\n"
            f"key_sha512_salted (e.g. Linux-based systems, Arista EOS, Juniper Junos): {self.key_sha512_salted}\n"
            f"key_apr1_salted (e.g. Apache HTTP Server htaccess): {self.key_apr1_salted}\n"
        )
