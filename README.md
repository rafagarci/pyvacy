# PyVacy

A simple password-based file encryption and decryption tool.

## Usage

```{text}
pyvacy.py [-h] [-e] [-d] [-k] [-p] [-D] INPUT_PATH [OUTPUT_PATH]

A simple password-based file encryption and decryption tool.

positional arguments:
  INPUT_PATH       path to input file or directory
  OUTPUT_PATH      path to output, if input is a file and this is omitted, the input file is overwritten

optional arguments:
  -h, --help       show this help message and exit
  -e, --encrypt    encrypt mode, this is the default
  -d, --decrypt    decrypt mode
  -k, --key        specify an encryption key instead of generating a password-based one
  -p, --print-key  print encryption key to console
  -D, --directory  apply to all files in the specified directory recursively while maintaining file names and directory structure. Symbolic link directories and
                   OUTPUT_PATH are omitted.
```

## Requirements

- `cryptography`
- `tqdm`

## Important Considerations

- This is essentially a password-based wrapper for the `Fernet` class in the `cryptography` library and depends entirely on that class's default behavior. See more details [here](https://cryptography.io/en/latest/fernet/#using-passwords-with-fernet).

- Basic tests were done to ensure basic functionality, but test specific use cases before using this for anything serious.

- This is not appropriate nor has been tested for large files. See [these limitations](https://cryptography.io/en/latest/fernet/#limitations).

- Use at your own risk.

## License

GNU GPLv3 © Rafael García
