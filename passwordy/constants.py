"""Constants for passwordy."""

PASSWORD_SPECIAL_CHARACTERS1: str = ".:,;+-=*#_<>()[]§~"
PASSWORD_SPECIAL_CHARACTERS2: str = "!?$&"

# Passwords with a length of 32 characters or less should not contain duplicate symbols in a row
# Let's say 'no character pair with two equal symbols'
PASSWORD_LENGTH_WITHOUT_REPETITION: int = 32

# Sane defaults for salt keys where applicable
SALT_LENGTH: int = 16
SALT_ADDITIONAL_CHARACTERS: str = "./"

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
