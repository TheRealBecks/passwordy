"""KeyRing to handle several Keys."""

import json
from abc import ABCMeta
from typing import ClassVar, TypedDict

from constants import KEY_DESCRIPTIONS
from keys import HexKey, Key, PasswordKey


class KeyRing:
    """Can hold several Keys in a dict."""

    class KeyType(TypedDict):
        """Type definition for key types."""

        hex_key: ABCMeta
        password: ABCMeta

    # TODO @therealbecks: Why hex_key but not password_key?
    key_types: ClassVar[KeyType] = {
        "hex_key": HexKey,
        "password": PasswordKey,
    }

    def __init__(self: "KeyRing") -> None:
        """Initialize KeyRing."""
        # self.keys: dict[str, list[dict[str, int | str]]] = {}
        self.keys: dict[str, list[Key]] = {}

    class KwargsType(TypedDict):
        """Type definition for kwargs."""

        password_plaintext: str
        password_lower_ascii: bool
        password_upper_ascii: bool
        password_digits: bool
        password_special_characters1: bool
        password_special_characters2: bool
        password_additional_characters: str
        allow_all_characters: bool
        show_plaintext_password: bool

    def add_key(
        self: "KeyRing",
        key_type: str,
        length: int,
        number_of_keys: int = 4,
        **kwargs: KwargsType
    ) -> None:
        """Add key to KeyRing."""
        for _ in range(number_of_keys):
            dict_key_name: str = key_type + "_" + str(length)
            if dict_key_name not in self.keys:
                self.keys[dict_key_name] = []
            self.keys[dict_key_name].append(
                self.key_types[key_type](length=length, **kwargs),
            )

    def delete_key(self: "KeyRing", key: Key) -> None:
        """Delete key from KeyRing."""
        if key in self.keys[key.hex_key_size_byte]:
            self.keys[key.hex_key_size_byte].remove(key)

    def json(self: "KeyRing") -> None:
        """Return keys as JSON."""
        return print(  # noqa: T201
            json.dumps(self.keys, default=lambda __o: __o.__dict__)
        )

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
