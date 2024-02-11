"""KeyRing to handle several Keys."""

import json
from typing import ClassVar

from constants import KEY_DESCRIPTIONS
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
