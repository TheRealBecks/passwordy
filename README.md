# Passwordy

Passwordy is a secure password and HEX key generator written in Python 🐍. It can be used on the command line as standalone tool or as input for another program when used with the JSON export. You can also import it as a module! 🧩

Sometimes it's really hard to work in the information technology. You can get annoyed by seemingly easy tasks like generating a password for a user for a (network) OS. ...but then... there are four different OSes in use at the company... and Linux... and you need some HEX keys for a MACsec secured darkfiber. Frustrating even under mighty Linux! 🐧

Not anymore! 😄

There are many tools out there that need HEX encoded passwords as their input. Passwordy will generate you a **plaintext password** and derives several **HEX keys** with different lengths and also (optionally salted) **password hashes** that can be used for the good OSes out there. 👍 (Unfortunately there's currently no support for bcrypted hashes that are needed for OSes like *BSD 😥)

If you already have a password but need the hashes you can also use Passwordy for that!

Passwordy will generate...

...the following **HEX keys** by default:

Byte | Symbols | Bit | Usage
---- | ------- | --- | -----
4    | 8       | 32  | I don't know, but maybe you will have a usage for that?
8    | 16      | 64  | ...or this one?
12   | 24      | 96  | ...and that one?
16   | 32      | 128 | AES128, MD5
20   | 40      | 160 | OSPFv3 SHA1 authentication, SHA1
24   | 48      | 192 | AES192
28   | 56      | 224 | SHA2 with 224 bit
32   | 64      | 256 | AES256, MACsec PSK CAK/key and CKN/name, SHA2 with 256 bit, SHA256
48   | 96      | 384 | SHA2 with 384 bit
64   | 128     | 512 | SHA2 with 512 bit

...**passwords** with the **lengths** of 4, 8, 12, 16, 20, 24, 28 and 32 characters.

...and will provide the **passwords** with the following **encodings**:
- MD5
- SHA1
- SHA224
- SHA256
- SHA384
- SHA512
- SHA 3 with 224 bit
- SHA 3 with 256 bit
- SHA 3 with 384 bit
- SHA 3 with 512 bit
- APR1 with 8 character salt for e.g. Apache HTTP Server htaccess
- MD5 with 4 character salt especially for Cisco IOS
- MD5 with 8 character salt
- SHA256 with 16 character salt for e.g. Cisco NX-OS
- SHA512 with 16 character salt for e.g. Linux-based systems, Arista EOS, Juniper Junos

## Requirements

Passwordy is compatible with **Python 3.9+** as it needs the `secrets` module introduced in 3.9. No additional external modules are needed for usage.

## Usage

Passwordy can be used on the command line as standalone program or as input for another program when used with the JSON output. You can also import it as a module in your awesome tools!

All HEX keys and hashed passwords listed on this site have been rendered garbage so nobody can copy them for usage on their systems. But you would have never done that, wouldn't you?! 😜

### Quickstart

Check it out:
```
python passwordy.py
```

...will result in:
```
HEX key 4 Byte, 8 symbols, 32 bit: 73xxxxfc
[...]
SHA2 with 512 bit:
HEX key 64 Byte, 128 symbols, 512 bit: 4988f2c19a05b53a8849875033f0b4b41fef3axxxxxxxxxxxxxxxxxxxxxxxxxxxxf2082ca2f633f8b49a9df942190e3f9f5f2514a6b6fdd570da88b2de64ddc2

key_plaintext (with 8 characters): tiUm6zo9
key_md5: 10a991dafdxxxxxxxxxxxx4974dbccbad
key_sha1: 77fe98375abc4xxxxxxxxxxxx9d29ed57e635da3c3
key_sha224: bb89856022ee5xxxxxxxxxxxx9ccafbce5df8e37e075a1c465fc724f
key_sha256: 302634bd20bb82fe12xxxxxxxxxxxx08be1c7c60a9ae544b811c1c5d5e36bd0b2
key_sha384: 7c26e41d81f2dd8a59560axxxxxxxxxxxx267bf0927603f75ab0a3d4ea365904bd115ff384dc0f4eb5f4d150661ea1220
key_sha512: 405f082d462a6f5f4f69016xxxxxxxxxxxxb0240571cbe668d92e71152b750d4b94e6619ab52506043baa5b7149c6b3a4cc0659062fb5e1a8fabe87951c404
key_sha3_224: fb61fdfdff358192574ff4d23xxxxxxxxxxxx3b31227308c96242f
key_sha3_256: ed2a66b8183db1e2ed6d4bd9f55xxxxxxxxxxxx8c9d4a554ab8187fd4b675a8c
key_sha3_384: 87db57611d841ff539a8521cbff46xxxxxxxxxxxxa0867118e3a51c6ce577e17f3c3eb135a2d7c80b29a4946f06
key_sha3_512: efa6baa3f3ac300fe7839b766878914axxxxxxxxxxxx94320ef3b23b65fa3a732d7191d0e4ec1e55fd73912264f5dfccd59aaf20aa5002528a5b3cf836b95
key_md5_salted: $1$Mlc5lFP9$WoMBy2k7xxxxxxxxxxxxZkKh9.
key_md5_salted_cisco_ios (e.g. Cisco IOS): $1$sDkc$NLSvsH.SxxxxxxxxxxxxH7zcsO0
key_sha256_salted (e.g. Cisco NX-OS): $5$ln9ZICoIJ2og/BDa$vVUqc3/N.HSExxxxxxxxxxxxYQbVXE5y6HUf.ztHrEYz1
key_sha512_salted (e.g. Linux-based systems, Arista EOS, Juniper Junos): $6$d5w9Fuf4a4BM6N4x$CFooMyg8ZwCwY0.Q2R1t5.5QUMt9J.Z.yUv561zxxxxxxxxxxxx5u7e.ItdpmMgPztLXMQDt6lTI8YH1
key_apr1_salted (e.g. Apache HTTP Server htaccess): $apr1$K9K5s3N7$T3IJ/.KTAxxxxxxxxxxxxNuv0

[...]
```

By default lower and upper ASCII characters and digits are used for password generation and leading digits are avoided so you can sefely use them for protocls like **BGP, OSPF and IS-IS**. If you need more secure passwords run it as follows:
```
python passwordy.py --password-special-characters1 --password-special-characters2
```

Check `--help` for further information about the characters used for the password generation.

If a password already exists, but the password hashes are needed use `--input-prompt`. `--password` is optional and will be set to `True` is any case:
```
python passwordy.py --password --input-prompt
```

### Available Options

Check the available options with `--help`:
```
python3 passwordy.py --help

usage: passwordy.py [-h] [--brief | --no-brief] [--hex-key | --no-hex-key] [-i | --input-prompt | --no-input-prompt] [-j | --json | --no-json] [-l LENGTH] [-n NUMBER_OF_KEYS] [--password | --no-password] [--password-lower-ascii | --no-password-lower-ascii] [--password-upper-ascii | --no-password-upper-ascii]
                    [--password-digits | --no-password-digits] [--password-special-characters1 | --no-password-special-characters1] [--password-special-characters2 | --no-password-special-characters2] [--password-additional-characters PASSWORD_ADDITIONAL_CHARACTERS] [-s | --secure | --no-secure]
                    [--show-plaintext-password | --no-show-plaintext-password] [--allow-all-characters | --no-allow-all-characters]

Secure password and HEX key generator.

options:
  -h, --help            show this help message and exit
  --brief, --no-brief   Brief output. (default: False)
  --hex-key, --no-hex-key
                        Generate HEX key. (default: False)
  -i, --input-prompt, --no-input-prompt
                        Provide your existing password in a secure prompt. (default: False)
  -j, --json, --no-json
                        Return keys as JSON. (default: False)
  -l LENGTH, --length LENGTH
                        Number of characters for passwords or the HEX key size in Byte: 1 Byte == 2 Symbols == 8 bit.
  -n NUMBER_OF_KEYS, --number-of-keys NUMBER_OF_KEYS
                        Number of keys, default value is 1.
  --password, --no-password
                        Generate passwords. (default: False)
  --password-lower-ascii, --no-password-lower-ascii
                        Use lower ASCII letters for password generation. (default: True)
  --password-upper-ascii, --no-password-upper-ascii
                        Use upper ASCII letters for password generation. (default: True)
  --password-digits, --no-password-digits
                        Use digits for password generation. (default: True)
  --password-special-characters1, --no-password-special-characters1
                        Use special characters for password generation including .:,;+-=*#_<>()[]~ (default: False)
  --password-special-characters2, --no-password-special-characters2
                        Use special characters for password generation including !?$& (default: False)
  --password-additional-characters PASSWORD_ADDITIONAL_CHARACTERS
                        Provide a string with characters for password generation. Using ' or " is not allowed as it will open Pandora's Box of insane automation bugs.
  -s, --secure, --no-secure
                        Secure passwords: Shortcut for --password-lower-ascii, --password-upper-ascii, --password-digits, --password-special-characters1, --password-special-characters2, (default: False)
  --show-plaintext-password, --no-show-plaintext-password
                        Show plaintext password in output. (default: False)
  --allow-all-characters, --no-allow-all-characters
                        Not recommended: Allow all characters for password generation: '"§ (and whitespace). (default: False)
```

### JSON Output

Use `--json` to get JSON output:
```
python3 passwordy.py --json
```

Pretty printed with `jq` the output looks like this (shortened):
```
{
  "hex_key_4": [
    {
      "hex_key_size_byte": 4,
      "key_size_symbols": 8,
      "key_size_bit": 32,
      "key_plaintext": "5dxxxxb0"
    },
  ],
  "password_8": [
    {
      "key_size_length": 8,
      "key_plaintext": "YAMHyz4K",
      "key_md5": "eea172389589xxxxxxxxxxxxcaff0bcc",
      "key_sha1": "292520a8ea15abb6aa066xxxxxxxxxxxx49aec0dc7",
      "key_sha224": "884769a77033cc29e26de53e7xxxxxxxxxxxx1ded7ea522c7d61293af",
      "key_sha256": "9f2c597ee1aac3044c112a47c8b1xxxxxxxxxxxxf1f141bb15dcf02803016dc",
      "key_sha384": "f8e9c42043617ab766549c33b8b1xxxxxxxxxxxxb140ff1d0cee6b977912b083b5a3d9dcb8a059db6fdcd1c8a542",
      "key_sha512": "b9264d12fae27136a91e462fe2bb6xxxxxxxxxxxx442ca3bde0ac9b4ce47d67f071bb1ccdd6757a2c2dfa130d29903ff64d00617b144f193e2fa5f238c5f87b2861",
      "key_sha3_224": "aa44963e2107f30b961ba09907b9xxxxxxxxxxxxd601d9fc50466f1c19",
      "key_sha3_256": "0cc62089e25fe22ce74fa95e544dxxxxxxxxxxxx0ad08f912f3df0ec5ee4707",
      "key_sha3_384": "35fa9f762dd13962caa6f45851886xxxxxxxxxxxxf73e928c473e96c0ee174ad5fbf44d6cea3bd2a5d471643004e604b",
      "key_sha3_512": "6cd3e563e644dd75d7a0798f440xxxxxxxxxxxx70b26b90c785a8220e5811b9e8c03c35323e0b54e980edc2c1ee33d4488fd6de2aa0396f2b45b36678",
      "key_md5_salted": "$1$k73AtnFj$mIhexxxxxxxxxxxxx9wIC.",
      "key_md5_salted_cisco_ios": "$1$SUMb$uUL9YwPPexxxxxxxxxxxxXCXz0.",
      "key_sha256_salted": "$5$Zzvog51vfwqHLMo2$GpZo3xxxxxxxxxxxxAM5NZeYh4Q6lgBe3eNkC",
      "key_sha512_salted": "$6$FtRtqeN6lAatXqWT$DY2hVU0xxxxxxxxxxxxsihX0pxNDrMllY8EYvD1FruYYOuCVuT81TQ5VFAa13qnMu5eIiov.",
      "key_apr1_salted": "$apr1$gGLKpvhW$xxxxxxxxxxxxjKkHd."
    }
  ],
}
```

You can also combine it with the options listed under `--help`.

### Examples

If a password already exists, but the password hashes are needed use `--input-prompt`. `--password` is optional and will be set to `True` is any case:
```
python passwordy.py --password --input-prompt
```

Generate 4 HEX keys with a length of 20 Byte (= 40 symbols = 160 bit):
```
python passwordy.py --hex-key -n 4 -l 20
OSPFv3 SHA1 authentication, SHA1:
HEX key 20 Byte, 40 symbols, 160 bit: ebbec2eedb6c3xxxxxxxxxxxxc525cf1c94173c5
HEX key 20 Byte, 40 symbols, 160 bit: 6f3b84503a061xxxxxxxxxxxx62feed92c444a80
HEX key 20 Byte, 40 symbols, 160 bit: 9ee20ba3b48ecxxxxxxxxxxxxf699480f23fd728
HEX key 20 Byte, 40 symbols, 160 bit: 63ad56f2b0686xxxxxxxxxxxxe00d68ab3a919f3
```

...as JSON output:
```
python passwordy.py --hex-key -n 4 -l 20 --json
```

Generate 16 (default value) passwords with a length of 24 characters and provide all hashes:
```
python passwordy.py --password -l 24
```

Generate 1 password with a length of 24 characters and provide all hashes:
```
python passwordy.py --password -l 24 -n 1
```

Generate 1 password with a length of 24 characters with special characters from `--password-special-characters1` and `--password-special-characters2` and provide all hashes. Check `--help` if you want to know which characters are used:
```
python passwordy.py --password -l 24 -n 1 --password-special-characters1 --password-special-characters2
```

Generate 1 password with a default length of 16 characters with lower and upper ASCII characters, digits and characters from `--password-additional-characters` and provide all hashes:
```
python passwordy.py --password --password-additional-characters ".-" -n 1
```

Generate 1 password with a default length of 16 characters with lowerASCII characters and digits and provide all hashes:
```
python passwordy.py --password --no-password_upper_ascii -n 1
```

Generate 1 password with a default length of 16 characters and digits only and provide all hashes. In that case the password can't be used for protocols like BGP:
```
python passwordy.py --password --no-password_upper_ascii --no-password_lower_ascii -n 1
```
