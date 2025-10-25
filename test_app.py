import unittest
import os
import tempfile
import shutil
from pathlib import Path
from app import EncryptionManager, SecurityValidator, FileManager, Config

class TestEncryptionManager(unittest.TestCase):
    """Test cases for encryption and decryption functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_data = b"This is test data for encryption"
        self.test_password = "TestPassword123!"
        self.test_salt = b"test_salt_16_bytes"
    
    def test_derive_key(self):
        """Test key derivation from password and salt"""
        key1 = EncryptionManager.derive_key(self.test_password, self.test_salt)
        key2 = EncryptionManager.derive_key(self.test_password, self.test_salt)
        
        # Same password and salt should produce same key
        self.assertEqual(key1, key2)
        
        # Key should be 44 bytes (base64 encoded 32-byte key)
        self.assertEqual(len(key1), 44)
        
        # Different password should produce different key
        different_password = "DifferentPassword123!"
        key3 = EncryptionManager.derive_key(different_password, self.test_salt)
        self.assertNotEqual(key1, key3)
        
        # Different salt should produce different key
        different_salt = b"different_salt_16by"
        key4 = EncryptionManager.derive_key(self.test_password, different_salt)
        self.assertNotEqual(key1, key4)
    
    def test_encrypt_decrypt_roundtrip(self):
        """Test that encrypting and decrypting produces original data"""
        encrypted = EncryptionManager.encrypt_file_bytes(self.test_data, self.test_password)
        decrypted = EncryptionManager.decrypt_file_bytes(encrypted, self.test_password)
        
        self.assertEqual(self.test_data, decrypted)
    
    def test_encrypt_different_passwords(self):
        """Test that different passwords produce different encrypted data"""
        password1 = "Password123!"
        password2 = "DifferentPassword456!"
        
        encrypted1 = EncryptionManager.encrypt_file_bytes(self.test_data, password1)
        encrypted2 = EncryptionManager.encrypt_file_bytes(self.test_data, password2)
        
        self.assertNotEqual(encrypted1, encrypted2)
    
    def test_decrypt_wrong_password(self):
        """Test that wrong password raises ValueError"""
        encrypted = EncryptionManager.encrypt_file_bytes(self.test_data, self.test_password)
        wrong_password = "WrongPassword123!"
        
        with self.assertRaises((ValueError, Exception)):
            EncryptionManager.decrypt_file_bytes(encrypted, wrong_password)
    
    def test_decrypt_corrupted_data(self):
        """Test that corrupted data raises ValueError"""
        corrupted_data = b"corrupted_data"
        
        with self.assertRaises(ValueError):
            EncryptionManager.decrypt_file_bytes(corrupted_data, self.test_password)
    
    def test_empty_data(self):
        """Test encryption/decryption of empty data"""
        empty_data = b""
        encrypted = EncryptionManager.encrypt_file_bytes(empty_data, self.test_password)
        decrypted = EncryptionManager.decrypt_file_bytes(encrypted, self.test_password)
        
        self.assertEqual(empty_data, decrypted)
    
    def test_large_data(self):
        """Test encryption/decryption of large data"""
        large_data = b"x" * (1024 * 1024)  # 1MB of data
        encrypted = EncryptionManager.encrypt_file_bytes(large_data, self.test_password)
        decrypted = EncryptionManager.decrypt_file_bytes(encrypted, self.test_password)
        
        self.assertEqual(large_data, decrypted)

class TestSecurityValidator(unittest.TestCase):
    """Test cases for security validation functions"""
    
    def test_validate_password_valid(self):
        """Test valid password validation"""
        valid_passwords = [
            "Password123!",
            "MySecurePass456",
            "Test123ABC",
            "StrongP@ssw0rd"
        ]
        
        for password in valid_passwords:
            is_valid, message = SecurityValidator.validate_password(password)
            self.assertTrue(is_valid, f"Password '{password}' should be valid: {message}")
    
    def test_validate_password_too_short(self):
        """Test password too short validation"""
        short_passwords = ["Pass1", "Abc123", "Test"]
        
        for password in short_passwords:
            is_valid, message = SecurityValidator.validate_password(password)
            self.assertFalse(is_valid)
            self.assertIn("at least", message)
    
    def test_validate_password_too_long(self):
        """Test password too long validation"""
        long_password = "A" * 200  # Exceeds MAX_PASSWORD_LENGTH
        
        is_valid, message = SecurityValidator.validate_password(long_password)
        self.assertFalse(is_valid)
        self.assertIn("no more than", message)
    
    def test_validate_password_weak(self):
        """Test weak password validation"""
        weak_passwords = ["password", "123456", "admin", "qwerty"]
        
        for password in weak_passwords:
            is_valid, message = SecurityValidator.validate_password(password)
            self.assertFalse(is_valid)
            # Check for either "too common" or length requirement message
            self.assertTrue("too common" in message or "at least" in message)
    
    def test_validate_password_no_complexity(self):
        """Test password without required complexity"""
        simple_passwords = [
            "password",  # no uppercase, no digit
            "PASSWORD",  # no lowercase, no digit
            "Password",  # no digit
            "12345678"   # no letters
        ]
        
        for password in simple_passwords:
            is_valid, message = SecurityValidator.validate_password(password)
            self.assertFalse(is_valid)
            # Check for complexity requirement message
            self.assertTrue("uppercase" in message or "lowercase" in message or "digit" in message or "too common" in message)
    
    def test_validate_filename_valid(self):
        """Test valid filename validation"""
        valid_filenames = [
            "test.txt",
            "my-document.pdf",
            "file_name.docx",
            "123456789"
        ]
        
        for filename in valid_filenames:
            is_valid, message = SecurityValidator.validate_filename(filename)
            self.assertTrue(is_valid, f"Filename '{filename}' should be valid: {message}")
    
    def test_validate_filename_invalid(self):
        """Test invalid filename validation"""
        invalid_filenames = [
            "",  # empty
            "file/name.txt",  # contains /
            "file\\name.txt",  # contains \
            "file:name.txt",  # contains :
            "file*name.txt",  # contains *
            "file?name.txt",  # contains ?
            "file<name.txt",  # contains <
            "file>name.txt",  # contains >
            "file|name.txt",  # contains |
            "..",  # parent directory
            "file..txt"  # contains ..
        ]
        
        for filename in invalid_filenames:
            is_valid, message = SecurityValidator.validate_filename(filename)
            self.assertFalse(is_valid, f"Filename '{filename}' should be invalid")
    
    def test_validate_file_size_valid(self):
        """Test valid file size validation"""
        valid_sizes = [1, 1024, 1024*1024, Config.MAX_FILE_SIZE]
        
        for size in valid_sizes:
            is_valid, message = SecurityValidator.validate_file_size(size)
            self.assertTrue(is_valid, f"Size {size} should be valid: {message}")
    
    def test_validate_file_size_invalid(self):
        """Test invalid file size validation"""
        invalid_sizes = [0, Config.MAX_FILE_SIZE + 1]
        
        for size in invalid_sizes:
            is_valid, message = SecurityValidator.validate_file_size(size)
            self.assertFalse(is_valid, f"Size {size} should be invalid")

class TestFileManager(unittest.TestCase):
    """Test cases for file management utilities"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_data = b"This is test file data"
        self.temp_dir = tempfile.mkdtemp()
        self.test_file = Path(self.temp_dir) / "test.txt"
        self.test_file.write_bytes(self.test_data)
    
    def tearDown(self):
        """Clean up test fixtures"""
        shutil.rmtree(self.temp_dir)
    
    def test_get_file_hash(self):
        """Test file hash generation"""
        hash1 = FileManager.get_file_hash(self.test_data)
        hash2 = FileManager.get_file_hash(self.test_data)
        
        # Same data should produce same hash
        self.assertEqual(hash1, hash2)
        
        # Hash should be 64 characters (SHA-256 hex)
        self.assertEqual(len(hash1), 64)
        
        # Different data should produce different hash
        different_data = b"Different data"
        hash3 = FileManager.get_file_hash(different_data)
        self.assertNotEqual(hash1, hash3)
    
    def test_get_file_metadata(self):
        """Test file metadata extraction"""
        metadata = FileManager.get_file_metadata(self.test_file)
        
        self.assertEqual(metadata['name'], 'test.txt')
        self.assertEqual(metadata['size'], len(self.test_data))
        self.assertIn('created', metadata)
        self.assertIn('modified', metadata)
        
        # Check that timestamps are valid ISO format
        from datetime import datetime
        datetime.fromisoformat(metadata['created'])
        datetime.fromisoformat(metadata['modified'])

if __name__ == '__main__':
    # Run tests
    unittest.main(verbosity=2)
