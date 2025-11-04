#!/usr/bin/env python3
"""
Test script for AES Encryption System
Demonstrates and validates encryption/decryption functionality
"""

import json
import sys
from aes_encryption import AESEncryption


def test_basic_encryption():
    """Test basic encryption and decryption"""
    print("🧪 Testing Basic Encryption/Decryption...")

    # Test data
    test_data = "This is a secret message for testing AES encryption!"

    # Initialize encryption
    password = "TestPassword123!"
    aes = AESEncryption(password=password)

    # Encrypt
    encrypted = aes.encrypt(test_data)

    # Decrypt
    decrypted = aes.decrypt(encrypted)

    # Verify
    if test_data == decrypted:
        print("✅ Basic encryption test PASSED")
        return True
    else:
        print("❌ Basic encryption test FAILED")
        print(f"Original:  {test_data}")
        print(f"Decrypted: {decrypted}")
        return False


def test_json_data():
    """Test encryption with JSON data"""
    print("🧪 Testing JSON Data Encryption...")

    # Complex JSON data
    test_data = {
        "user": {
            "id": 12345,
            "name": "John Doe",
            "email": "john.doe@example.com"
        },
        "account": {
            "balance": 1500.75,
            "currency": "USD",
            "status": "active"
        },
        "security": {
            "credit_card": "4532-1234-5678-9012",
            "cvv": "123",
            "expiry": "12/25"
        }
    }

    # Initialize encryption
    password = "SecurePassword456!"
    aes = AESEncryption(password=password)

    # Convert to JSON string
    json_string = json.dumps(test_data, indent=2)

    # Encrypt
    encrypted = aes.encrypt(json_string)

    # Decrypt
    decrypted_json = aes.decrypt(encrypted)

    # Parse back to JSON
    decrypted_data = json.loads(decrypted_json)

    # Verify
    if test_data == decrypted_data:
        print("✅ JSON encryption test PASSED")
        return True
    else:
        print("❌ JSON encryption test FAILED")
        return False


def test_key_generation():
    """Test secure key generation"""
    print("🧪 Testing Key Generation...")

    try:
        key = AESEncryption.generate_secure_key()
        salt = AESEncryption.generate_salt()

        # Verify key format
        import base64
        decoded_key = base64.b64decode(key)
        decoded_salt = base64.b64decode(salt)

        if len(decoded_key) == 32 and len(decoded_salt) == 16:
            print("✅ Key generation test PASSED")
            return True
        else:
            print("❌ Key generation test FAILED")
            return False
    except Exception as e:
        print(f"❌ Key generation test FAILED: {e}")
        return False


def test_different_passwords():
    """Test that different passwords produce different results"""
    print("🧪 Testing Password Security...")

    test_data = "Test message"

    # Encrypt with different passwords
    aes1 = AESEncryption(password="Password1")
    aes2 = AESEncryption(password="Password2")

    encrypted1 = aes1.encrypt(test_data)
    encrypted2 = aes2.encrypt(test_data)

    # Results should be different
    if (encrypted1['ciphertext'] != encrypted2['ciphertext'] and
        encrypted1['iv'] != encrypted2['iv'] and
        encrypted1['salt'] != encrypted2['salt']):
        print("✅ Password security test PASSED")
        return True
    else:
        print("❌ Password security test FAILED")
        return False


def test_error_handling():
    """Test error handling with invalid data"""
    print("🧪 Testing Error Handling...")

    aes = AESEncryption(password="TestPassword")

    # Test with invalid encrypted data
    invalid_data = {
        "ciphertext": "invalid",
        "iv": "invalid",
        "salt": "invalid"
    }

    try:
        aes.decrypt(invalid_data)
        print("❌ Error handling test FAILED - should have raised exception")
        return False
    except (ValueError, Exception):
        print("✅ Error handling test PASSED")
        return True


def test_large_data():
    """Test encryption with larger data"""
    print("🧪 Testing Large Data Encryption...")

    # Generate large test data
    large_data = "A" * 10000  # 10KB of data

    aes = AESEncryption(password="LargeDataTest123!")

    try:
        # Encrypt
        encrypted = aes.encrypt(large_data)

        # Decrypt
        decrypted = aes.decrypt(encrypted)

        # Verify
        if large_data == decrypted:
            print("✅ Large data test PASSED")
            return True
        else:
            print("❌ Large data test FAILED")
            return False
    except Exception as e:
        print(f"❌ Large data test FAILED: {e}")
        return False


def run_performance_test():
    """Run performance test"""
    print("🧪 Running Performance Test...")

    import time

    # Test data sizes
    sizes = [1024, 10240, 102400]  # 1KB, 10KB, 100KB
    password = "PerformanceTest123!"

    for size in sizes:
        test_data = "X" * size
        aes = AESEncryption(password=password)

        # Measure encryption time
        start_time = time.time()
        encrypted = aes.encrypt(test_data)
        encrypt_time = time.time() - start_time

        # Measure decryption time
        start_time = time.time()
        decrypted = aes.decrypt(encrypted)
        decrypt_time = time.time() - start_time

        print(f"  Size: {size/1024:.0f}KB - Encrypt: {encrypt_time:.3f}s, Decrypt: {decrypt_time:.3f}s")


def main():
    """Run all tests"""
    print("🔐 AES Encryption System - Test Suite")
    print("=" * 50)

    tests = [
        test_basic_encryption,
        test_json_data,
        test_key_generation,
        test_different_passwords,
        test_error_handling,
        test_large_data
    ]

    passed = 0
    total = len(tests)

    for test in tests:
        if test():
            passed += 1
        print()

    # Performance test
    run_performance_test()
    print()

    # Summary
    print("=" * 50)
    print(f"📊 Test Results: {passed}/{total} tests passed")

    if passed == total:
        print("🎉 All tests PASSED! System is working correctly.")
        return 0
    else:
        print("⚠️  Some tests FAILED. Please check the implementation.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
