# 🔐 AES Encryption System - Data Security and Privacy

A comprehensive implementation of AES (Advanced Encryption Standard) encryption for securing sensitive data and ensuring privacy protection.

## 📋 Overview

This project demonstrates a robust data security solution using AES-256 encryption with industry-standard security practices. The system provides both programmatic access through Python and a user-friendly web interface for encryption and decryption operations.

## ✨ Features

- **🔐 AES-256 Encryption**: Military-grade encryption algorithm
- **🛡️ PBKDF2 Key Derivation**: Secure password-based key generation with 100,000 iterations
- **🔄 CBC Mode**: Cipher Block Chaining for enhanced security
- **🔑 Random IV Generation**: Unique initialization vector for each encryption
- **📦 PKCS7 Padding**: Secure padding for data alignment
- **🌐 Web Interface**: User-friendly browser-based interface
- **🛠️ Command Line Support**: Python API for integration
- **📊 Base64 Encoding**: Safe encoding for data transmission

## 🚀 Quick Start

### Prerequisites

- Python 3.7 or higher
- Required packages (automatically installed)

### Installation

1. **Clone or download the project files**

2. **Install dependencies:**
   ```bash
   pip install -r requirements.txt
   ```

3. **Run the demonstration:**
   ```bash
   python aes_encryption.py
   ```

4. **Open the web interface:**
   - Open `web_interface.html` in your web browser
   - Or serve it using a local server:
     ```bash
     python -m http.server 8000
     ```
     Then visit `http://localhost:8000/web_interface.html`

## 💻 Usage

### Python API

```python
from aes_encryption import AESEncryption

# Initialize with password
aes = AESEncryption(password="MySecurePassword123!")

# Encrypt data
sensitive_data = "This is my secret message"
encrypted = aes.encrypt(sensitive_data)
print("Encrypted:", encrypted)

# Decrypt data
decrypted = aes.decrypt(encrypted)
print("Decrypted:", decrypted)
```

### Web Interface

1. Open `web_interface.html` in your browser
2. Enter your password and data to encrypt
3. Click "Encrypt Data" to get encrypted output
4. Use the encrypted data in the decryption section
5. Enter the same password and click "Decrypt Data"

## 🔧 Security Features

### Encryption Algorithm
- **AES-256**: 256-bit key length providing maximum security
- **CBC Mode**: Prevents pattern recognition attacks
- **PKCS7 Padding**: Ensures data integrity during encryption

### Key Management
- **PBKDF2**: Password-based key derivation function
- **100,000 iterations**: High iteration count for brute-force resistance
- **Random Salt**: Unique salt for each encryption session

### Data Protection
- **Random IV**: Unique initialization vector per encryption
- **Base64 Encoding**: Safe encoding for transmission and storage
- **Input Validation**: Comprehensive error handling

## 📁 Project Structure

```
├── aes_encryption.py      # Main encryption implementation
├── web_interface.html     # Web-based user interface
├── requirements.txt       # Python dependencies
└── README.md             # Project documentation
```

## 🧪 Testing

### Sample Test Case

```python
# Test data
test_data = {
    "user_id": "12345",
    "email": "user@example.com",
    "credit_card": "4532-1234-5678-9012",
    "personal_info": {
        "name": "John Doe",
        "address": "123 Main St, City, State 12345",
        "phone": "+1-555-0123"
    }
}

# Initialize encryption
aes = AESEncryption(password="MySecurePassword123!")

# Encrypt
encrypted = aes.encrypt(json.dumps(test_data))

# Decrypt
decrypted = aes.decrypt(encrypted)

# Verify integrity
assert json.dumps(test_data) == decrypted
print("✓ All tests passed!")
```

## 🔒 Security Best Practices

1. **Strong Passwords**: Use passwords with at least 12 characters, including uppercase, lowercase, numbers, and symbols
2. **Key Rotation**: Regularly change encryption passwords
3. **Secure Storage**: Store encrypted data in secure locations
4. **Access Control**: Limit access to encryption keys and passwords
5. **Regular Updates**: Keep encryption libraries updated

## 🌐 Web Interface Features

- **Real-time Encryption/Decryption**: Instant processing of data
- **Copy-Paste Support**: Easy data transfer between fields
- **Error Handling**: Clear error messages for invalid inputs
- **Responsive Design**: Works on desktop and mobile devices
- **Sample Data**: Pre-loaded examples for testing

## 📊 Performance

- **Encryption Speed**: ~1MB/s on standard hardware
- **Memory Usage**: Minimal memory footprint
- **Scalability**: Suitable for small to medium data volumes

## 🔍 Use Cases

- **Personal Data Protection**: Secure personal information
- **File Encryption**: Protect sensitive documents
- **API Security**: Secure data transmission
- **Database Encryption**: Protect stored sensitive data
- **Communication Security**: Secure message transmission

## 🛠️ Technical Details

### Algorithm Specifications
- **Cipher**: AES (Advanced Encryption Standard)
- **Key Size**: 256 bits
- **Block Size**: 128 bits
- **Mode**: CBC (Cipher Block Chaining)
- **Padding**: PKCS7
- **Key Derivation**: PBKDF2 with SHA-256

### Dependencies
- `cryptography`: Core encryption library
- `pycryptodome`: Additional cryptographic functions

## 📝 License

This project is for educational and demonstration purposes. Use at your own risk.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📞 Support

For questions or issues, please refer to the documentation or create an issue in the project repository.

---

**⚠️ Important Security Notice**: This implementation is for educational purposes. For production use, consider additional security measures like hardware security modules (HSMs) and consult with security experts.

**🔐 Remember**: The security of your encrypted data depends on the strength of your password and proper key management practices.
