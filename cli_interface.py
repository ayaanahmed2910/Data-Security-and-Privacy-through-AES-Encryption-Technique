#!/usr/bin/env python3
"""
Command Line Interface for AES Encryption System
Provides easy-to-use commands for data encryption and decryption
"""

import sys
import json
import argparse
from aes_encryption import AESEncryption


class CLIInterface:
    """Command Line Interface for AES Encryption"""

    def __init__(self):
        self.aes = None

    def setup_encryption(self, password: str, salt: str = None):
        """Initialize AES encryption with password"""
        try:
            if salt:
                import base64
                salt_bytes = base64.b64decode(salt)
                self.aes = AESEncryption(password=password, salt=salt_bytes)
            else:
                self.aes = AESEncryption(password=password)
            return True
        except Exception as e:
            print(f"❌ Error setting up encryption: {e}")
            return False

    def encrypt_data(self, data: str, output_file: str = None):
        """Encrypt data and optionally save to file"""
        if not self.aes:
            print("❌ Please set up encryption first with --password")
            return False

        try:
            encrypted = self.aes.encrypt(data)

            if output_file:
                with open(output_file, 'w') as f:
                    json.dump(encrypted, f, indent=2)
                print(f"✅ Data encrypted and saved to {output_file}")
            else:
                print("\n🔐 Encrypted Data:")
                print(json.dumps(encrypted, indent=2))

            return True
        except Exception as e:
            print(f"❌ Encryption failed: {e}")
            return False

    def decrypt_data(self, encrypted_data: str, output_file: str = None):
        """Decrypt data and optionally save to file"""
        if not self.aes:
            print("❌ Please set up encryption first with --password")
            return False

        try:
            # Try to parse as JSON first
            try:
                data = json.loads(encrypted_data)
            except json.JSONDecodeError:
                print("❌ Invalid encrypted data format. Expected JSON.")
                return False

            decrypted = self.aes.decrypt(data)

            if output_file:
                with open(output_file, 'w') as f:
                    f.write(decrypted)
                print(f"✅ Data decrypted and saved to {output_file}")
            else:
                print("\n🔓 Decrypted Data:")
                print(decrypted)

            return True
        except Exception as e:
            print(f"❌ Decryption failed: {e}")
            return False

    def generate_key(self):
        """Generate a secure random key"""
        key = AESEncryption.generate_secure_key()
        salt = AESEncryption.generate_salt()

        print("\n🔑 Generated Secure Key:")
        print(f"Key:  {key}")
        print(f"Salt: {salt}")
        print("\n⚠️  Save these values securely! You cannot recover your data without them.")

    def show_info(self):
        """Show system information"""
        print("\n📋 AES Encryption System Information:")
        print("=" * 50)
        print("Algorithm: AES-256-CBC")
        print("Key Derivation: PBKDF2 (100,000 iterations)")
        print("Padding: PKCS7")
        print("Encoding: Base64")
        print("Security Level: Military Grade")
        print("=" * 50)


def main():
    """Main CLI function"""
    parser = argparse.ArgumentParser(
        description="AES Encryption System - Secure Data Protection",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Encrypt a message
  python cli_interface.py encrypt --password "MyPassword123" --data "Secret message"

  # Encrypt from file
  python cli_interface.py encrypt --password "MyPassword123" --file input.txt --output encrypted.json

  # Decrypt data
  python cli_interface.py decrypt --password "MyPassword123" --data '{"ciphertext": "...", "iv": "...", "salt": "..."}'

  # Generate secure key
  python cli_interface.py generate-key

  # Show system info
  python cli_interface.py info
        """
    )

    parser.add_argument('--password', '-p', help='Encryption password')
    parser.add_argument('--salt', '-s', help='Salt for key derivation (base64 encoded)')

    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Encrypt command
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt data')
    encrypt_parser.add_argument('--data', '-d', help='Data to encrypt')
    encrypt_parser.add_argument('--file', '-f', help='File containing data to encrypt')
    encrypt_parser.add_argument('--output', '-o', help='Output file for encrypted data')

    # Decrypt command
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt data')
    decrypt_parser.add_argument('--data', '-d', help='Encrypted data (JSON format)')
    decrypt_parser.add_argument('--file', '-f', help='File containing encrypted data')
    decrypt_parser.add_argument('--output', '-o', help='Output file for decrypted data')

    # Generate key command
    subparsers.add_parser('generate-key', help='Generate secure encryption key')

    # Info command
    subparsers.add_parser('info', help='Show system information')

    args = parser.parse_args()

    # Initialize CLI
    cli = CLIInterface()

    # Handle commands
    if args.command == 'encrypt':
        # Setup encryption
        if not args.password:
            print("❌ Password is required for encryption")
            sys.exit(1)

        if not cli.setup_encryption(args.password, args.salt):
            sys.exit(1)

        # Get data to encrypt
        data = None
        if args.data:
            data = args.data
        elif args.file:
            try:
                with open(args.file, 'r') as f:
                    data = f.read()
            except FileNotFoundError:
                print(f"❌ File not found: {args.file}")
                sys.exit(1)
            except Exception as e:
                print(f"❌ Error reading file: {e}")
                sys.exit(1)
        else:
            print("❌ Please provide data with --data or --file")
            sys.exit(1)

        # Encrypt data
        cli.encrypt_data(data, args.output)

    elif args.command == 'decrypt':
        # Setup encryption
        if not args.password:
            print("❌ Password is required for decryption")
            sys.exit(1)

        if not cli.setup_encryption(args.password, args.salt):
            sys.exit(1)

        # Get encrypted data
        encrypted_data = None
        if args.data:
            encrypted_data = args.data
        elif args.file:
            try:
                with open(args.file, 'r') as f:
                    encrypted_data = f.read()
            except FileNotFoundError:
                print(f"❌ File not found: {args.file}")
                sys.exit(1)
            except Exception as e:
                print(f"❌ Error reading file: {e}")
                sys.exit(1)
        else:
            print("❌ Please provide encrypted data with --data or --file")
            sys.exit(1)

        # Decrypt data
        cli.decrypt_data(encrypted_data, args.output)

    elif args.command == 'generate-key':
        cli.generate_key()

    elif args.command == 'info':
        cli.show_info()

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
