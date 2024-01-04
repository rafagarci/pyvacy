#!/usr/bin/python3
'''
PyVacy: A simple password-based file encryption and decryption tool.
'''
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from getpass import getpass
from tqdm import tqdm
import argparse
import os

def confirmed_input(input_type: str) -> str:
    '''
    Prompts an user using getpass twice, confirming that the same input is
    passed each time.

    Parameters:
    - input_type: str
        What the user will be asked to input.

    Raises:
    - Exception
        If the inputs provided do not match.

    Returns:
    str
        Obtained input.
    '''
    input_1 = getpass(prompt=f'{input_type}: '.capitalize())
    input_2 = getpass(prompt=f'Confirm {input_type}: ')
    if input_1!= input_2:
        print(f'{input_type}s do not match.'.capitalize())
        exit(-1)
    else:
        return input_1

def key_gen() -> bytes:
    '''
    Encryption key generation function.

    Returns:
    bytes
        Encryption key.
    '''
    salt = b'This salty salt unfortunately does not change :('
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=600001)
    return urlsafe_b64encode(kdf.derive(confirmed_input('password').encode()))

def encrypt(input_path: str, output_path: str, fernet: Fernet) -> None:
    '''
    File encryption function.

    Parameters:
    - input_path: str
        Path to input.
    - output_path: str
        Path to output.
    - fernet: Fernet
        Fernet object used for encryption.

    Returns:
    None
    '''
    with open(input_path, 'rb') as f:
        # Encrypt data
        encrypted = fernet.encrypt(f.read())

    with open(output_path, 'wb') as f:
        # Store in the destination file
        f.write(encrypted)

def decrypt(input_path: str, output_path: str, fernet: Fernet):
    '''
    File decryption function.

    Parameters:
    - input_path: str
        Path to input.
    - output_path: str
        Path to output.
    - fernet: Fernet
        Fernet object used for decryption.

    Returns:
    None
    '''
    with open(input_path, 'rb') as f:
        # Read the data
        encrypted = f.read()

    with open(output_path, 'wb') as f:
        # Decrypt and store in the destination file
        f.write(fernet.decrypt(encrypted))

if __name__ == '__main__':
    '''
    Main execution function.
    '''
    parser = argparse.ArgumentParser(prog='pyvacy.py', description='A simple password-based file encryption and decryption tool.')
    parser.add_argument('-e', '--encrypt', help='encrypt mode, this is the default', action='store_true')
    parser.add_argument('-d', '--decrypt', help='decrypt mode', action='store_true')
    parser.add_argument('-k', '--key', help='specify an encryption key instead of generating a password-based one', action='store_true')
    parser.add_argument('-p', '--print-key', help='print encryption key to console', action='store_true')
    parser.add_argument('-D', '--directory', help='apply to all files in the specified directory recursively while maintaining file names and directory structure. Symbolic link directories and OUTPUT_PATH are omitted.', action='store_true')
    parser.add_argument('input_path', help='path to input file or directory', metavar='INPUT_PATH')
    parser.add_argument('output_path', nargs='?', help='path to output, if input is a file and this is omitted, the input file is overwritten', metavar='OUTPUT_PATH')
    args = parser.parse_args()

    # Check that encryption and decryption modes were not both specified
    if args.encrypt and args.decrypt:
        raise Exception('Both encryption and decryption mode were specified')

    # Default to encryption if neither was specified
    if not args.encrypt and not args.decrypt:
        args.encrypt = True

    # Get absolute paths of input and output
    input_abs_path = os.path.abspath(args.input_path)
    output_abs_path = input_abs_path if not args.output_path else os.path.abspath(args.output_path)

    # Invalid cases
    if args.directory and not os.path.isdir(input_abs_path):
        raise Exception('Directory encryption mode was specified but input is not a directory.')
    if os.path.isdir(input_abs_path) and not args.directory:
        raise Exception('Input is a directory but directory encryption mode was not specified.')

    # Obtain encryption key
    encryption_key = key_gen() if not args.key else confirmed_input('encryption key').encode()
    if args.print_key:
        print('Encryption key: %s' % encryption_key.decode())

    # Instantiate Fernet object
    fernet=Fernet(encryption_key)

    # Choose encryption or decryption function based on the selected mode
    mode_function = encrypt if args.encrypt else decrypt if args.decrypt else None

    # Regular file case
    if not args.directory:
        mode_function(input_path=input_abs_path, output_path=output_abs_path, fernet=fernet)

    # Directory case
    else:
        for dir_path, _, files in os.walk(input_abs_path, onerror=lambda x: print(x)):
            print('Processing: %s' % dir_path)
            for f in tqdm(files):
                path = os.path.join(dir_path, f)
                mode_function(input_path=path, output_path=path, fernet=fernet)
