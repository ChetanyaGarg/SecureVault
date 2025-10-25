import os
import base64
import logging
import hashlib
import time
from datetime import datetime
from typing import Optional, Dict, Any
from pathlib import Path

from flask import (
    Flask,
    request,
    redirect,
    url_for,
    render_template,
    send_from_directory,
    flash,
    jsonify,
    abort,
)
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
import secrets
import socket
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configuration
class Config:
    # Security settings
    MAX_FILE_SIZE = int(os.getenv('MAX_FILE_SIZE', 100 * 1024 * 1024))  # 100MB default
    MIN_PASSWORD_LENGTH = int(os.getenv('MIN_PASSWORD_LENGTH', 8))
    MAX_PASSWORD_LENGTH = int(os.getenv('MAX_PASSWORD_LENGTH', 128))
    PBKDF2_ITERATIONS = int(os.getenv('PBKDF2_ITERATIONS', 400_000))
    
    # File storage
    UPLOAD_DIR = Path(os.getenv('UPLOAD_DIR', 'uploads'))
    ALLOWED_EXTENSIONS = set(os.getenv('ALLOWED_EXTENSIONS', '').split(',')) if os.getenv('ALLOWED_EXTENSIONS') else None
    
    # Application settings
    SECRET_KEY = os.getenv('SECRET_KEY', secrets.token_hex(32))
    DEBUG = os.getenv('DEBUG', 'False').lower() == 'true'
    HOST = os.getenv('HOST', '0.0.0.0')
    PORT = int(os.getenv('PORT', 8080))
    
    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')
    LOG_FILE = os.getenv('LOG_FILE', 'app.log')

# Initialize Flask app
app = Flask(__name__)
app.config.from_object(Config)

# Setup logging
logging.basicConfig(
    level=getattr(logging, Config.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(Config.LOG_FILE),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Create upload directory
Config.UPLOAD_DIR.mkdir(exist_ok=True)

# Security utilities
class SecurityValidator:
    @staticmethod
    def validate_password(password: str) -> tuple[bool, str]:
        """Validate password strength"""
        if len(password) < Config.MIN_PASSWORD_LENGTH:
            return False, f"Password must be at least {Config.MIN_PASSWORD_LENGTH} characters long"
        
        if len(password) > Config.MAX_PASSWORD_LENGTH:
            return False, f"Password must be no more than {Config.MAX_PASSWORD_LENGTH} characters long"
        
        # Check for common weak passwords
        weak_passwords = ['password', '123456', 'admin', 'qwerty', 'letmein']
        if password.lower() in weak_passwords:
            return False, "Password is too common. Please choose a stronger password"
        
        # Check for basic complexity
        has_upper = any(c.isupper() for c in password)
        has_lower = any(c.islower() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password)
        
        if not (has_upper and has_lower and has_digit):
            return False, "Password must contain at least one uppercase letter, one lowercase letter, and one digit"
        
        return True, "Password is valid"
    
    @staticmethod
    def validate_filename(filename: str) -> tuple[bool, str]:
        """Validate filename"""
        if not filename or len(filename.strip()) == 0:
            return False, "Filename cannot be empty"
        
        if len(filename) > 255:
            return False, "Filename is too long (max 255 characters)"
        
        # Check for dangerous characters
        dangerous_chars = ['..', '/', '\\', ':', '*', '?', '"', '<', '>', '|']
        for char in dangerous_chars:
            if char in filename:
                return False, f"Filename contains invalid character: {char}"
        
        return True, "Filename is valid"
    
    @staticmethod
    def validate_file_size(file_size: int) -> tuple[bool, str]:
        """Validate file size"""
        if file_size > Config.MAX_FILE_SIZE:
            return False, f"File size exceeds maximum allowed size of {Config.MAX_FILE_SIZE // (1024*1024)}MB"
        
        if file_size == 0:
            return False, "File cannot be empty"
        
        return True, "File size is valid"

# Encryption utilities
class EncryptionManager:
    @staticmethod
    def derive_key(password: str, salt: bytes, iterations: int = None) -> bytes:
        """Derive a 32-byte key for Fernet from a password and salt"""
        if iterations is None:
            iterations = Config.PBKDF2_ITERATIONS
            
        password_bytes = password.encode("utf-8")
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA512(),
            length=32,
            salt=salt,
            iterations=iterations,
            backend=default_backend(),
        )
        return base64.urlsafe_b64encode(kdf.derive(password_bytes))
    
    @staticmethod
    def encrypt_file_bytes(data: bytes, password: str) -> bytes:
        """Encrypt file data with password"""
        salt = secrets.token_bytes(16)
        key = EncryptionManager.derive_key(password, salt)
        f = Fernet(key)
        token = f.encrypt(data)
        return salt + token
    
    @staticmethod
    def decrypt_file_bytes(blob: bytes, password: str) -> bytes:
        """Decrypt file data with password"""
        if len(blob) < 17:
            raise ValueError("Invalid encrypted data")
        
        salt = blob[:16]
        token = blob[16:]
        key = EncryptionManager.derive_key(password, salt)
        
        try:
            f = Fernet(key)
            return f.decrypt(token)
        except InvalidSignature:
            raise ValueError("Invalid password or corrupted data")

# File management utilities
class FileManager:
    @staticmethod
    def get_file_hash(data: bytes) -> str:
        """Generate SHA-256 hash of file data"""
        return hashlib.sha256(data).hexdigest()
    
    @staticmethod
    def get_file_metadata(file_path: Path) -> Dict[str, Any]:
        """Get file metadata"""
        stat = file_path.stat()
        return {
            'name': file_path.name,
            'size': stat.st_size,
            'created': datetime.fromtimestamp(stat.st_ctime).isoformat(),
            'modified': datetime.fromtimestamp(stat.st_mtime).isoformat(),
        }
    
    @staticmethod
    def list_encrypted_files() -> list[Dict[str, Any]]:
        """List all encrypted files with metadata"""
        files = []
        for file_path in Config.UPLOAD_DIR.iterdir():
            if file_path.is_file() and file_path.suffix == '.enc':
                files.append(FileManager.get_file_metadata(file_path))
        return sorted(files, key=lambda x: x['modified'], reverse=True)

# Routes
@app.route("/", methods=["GET", "POST"])
def index():
    """Main page for uploading and listing files"""
    if request.method == "POST":
        return handle_file_upload()
    
    files = FileManager.list_encrypted_files()
    return render_template("index.html", files=files)

def handle_file_upload():
    """Handle file upload and encryption"""
    try:
        # Get form data
        file = request.files.get("file")
        password = request.form.get("password", "")
        custom_name = request.form.get("custom_name", "").strip()
        
        # Validate inputs
        if not file or file.filename == "":
            flash("No file selected.", "error")
            return redirect(request.url)
        
        if not password:
            flash("Password required.", "error")
            return redirect(request.url)
        
        if not custom_name:
            flash("Please enter a file name to store with.", "error")
            return redirect(request.url)
        
        # Security validations
        is_valid, message = SecurityValidator.validate_password(password)
        if not is_valid:
            flash(f"Password validation failed: {message}", "error")
            return redirect(request.url)
        
        is_valid, message = SecurityValidator.validate_filename(custom_name)
        if not is_valid:
            flash(f"Filename validation failed: {message}", "error")
            return redirect(request.url)
        
        # Read and validate file
        file.seek(0, 2)  # Seek to end
        file_size = file.tell()
        file.seek(0)  # Reset to beginning
        
        is_valid, message = SecurityValidator.validate_file_size(file_size)
        if not is_valid:
            flash(f"File validation failed: {message}", "error")
            return redirect(request.url)
        
        data = file.read()
        
        # Check file extension if restrictions are set
        if Config.ALLOWED_EXTENSIONS:
            file_ext = Path(file.filename).suffix.lower()
            if file_ext not in Config.ALLOWED_EXTENSIONS:
                flash(f"File type not allowed. Allowed types: {', '.join(Config.ALLOWED_EXTENSIONS)}", "error")
                return redirect(request.url)
        
        # Generate secure filename
        filename = secure_filename(custom_name)
        stored_name = f"{filename}.enc"
        stored_path = Config.UPLOAD_DIR / stored_name
        
        # Check if file already exists
        if stored_path.exists():
            flash(f"A file named '{stored_name}' already exists. Please choose another name.", "error")
            return redirect(request.url)
        
        # Encrypt and store file
        enc_blob = EncryptionManager.encrypt_file_bytes(data, password)
        stored_path.write_bytes(enc_blob)
        
        # Log successful upload
        file_hash = FileManager.get_file_hash(data)
        logger.info(f"File uploaded successfully: {stored_name}, size: {file_size}, hash: {file_hash}")
        
        flash(f"File successfully encrypted and stored as: {stored_name}", "success")
        return redirect(url_for("index"))
        
    except Exception as e:
        logger.error(f"Error during file upload: {str(e)}")
        flash("An error occurred during file upload. Please try again.", "error")
        return redirect(request.url)

@app.route("/download/<path:fname>", methods=["GET", "POST"])
def download(fname):
    """Download and decrypt file"""
    try:
        path = Config.UPLOAD_DIR / fname
        
        if not path.exists():
            flash("File not found.", "error")
            return redirect(url_for("index"))
        
        if request.method == "POST":
            password = request.form.get("password", "")
            if not password:
                flash("Password required.", "error")
                return redirect(request.url)
            
            try:
                blob = path.read_bytes()
                data = EncryptionManager.decrypt_file_bytes(blob, password)
                
                # Log successful download
                logger.info(f"File downloaded successfully: {fname}")
                
                return (
                    data,
                    200,
                    {
                        "Content-Type": "application/octet-stream",
                        "Content-Disposition": f'attachment; filename="{fname.replace(".enc", "")}"',
                        "Content-Length": str(len(data)),
                    },
                )
            except ValueError as e:
                logger.warning(f"Decryption failed for {fname}: {str(e)}")
                flash("Decryption failed: wrong password or corrupted file.", "error")
                return redirect(request.url)
        
        return render_template("download.html", fname=fname)
        
    except Exception as e:
        logger.error(f"Error during file download: {str(e)}")
        flash("An error occurred during file download. Please try again.", "error")
        return redirect(url_for("index"))

@app.route("/api/files", methods=["GET"])
def api_files():
    """API endpoint to list files"""
    try:
        files = FileManager.list_encrypted_files()
        return jsonify({"files": files, "count": len(files)})
    except Exception as e:
        logger.error(f"Error in API files endpoint: {str(e)}")
        return jsonify({"error": "Internal server error"}), 500

@app.route("/api/health", methods=["GET"])
def api_health():
    """Health check endpoint"""
    return jsonify({
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "version": "2.0.0",
        "name": "SecureVault"
    })

@app.errorhandler(413)
def too_large(e):
    """Handle file too large error"""
    flash(f"File too large. Maximum size allowed: {Config.MAX_FILE_SIZE // (1024*1024)}MB", "error")
    return redirect(url_for("index"))

@app.errorhandler(404)
def not_found(e):
    """Handle 404 errors"""
    return render_template("error.html", error="Page not found"), 404

@app.errorhandler(500)
def internal_error(e):
    """Handle 500 errors"""
    logger.error(f"Internal server error: {str(e)}")
    return render_template("error.html", error="Internal server error"), 500

if __name__ == "__main__":
    # Get LAN IP address
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        lan_ip = s.getsockname()[0]
        s.close()
    except Exception:
        lan_ip = "127.0.0.1"
    
    logger.info("Starting SecureVault Application")
    logger.info(f"Configuration: MAX_FILE_SIZE={Config.MAX_FILE_SIZE}, PBKDF2_ITERATIONS={Config.PBKDF2_ITERATIONS}")
    
    print("\n🔒 SecureVault Application")
    print("=" * 50)
    print(f"📁 Upload Directory: {Config.UPLOAD_DIR.absolute()}")
    print(f"🔐 Max File Size: {Config.MAX_FILE_SIZE // (1024*1024)}MB")
    print(f"🛡️  Min Password Length: {Config.MIN_PASSWORD_LENGTH}")
    print(f"🔄 PBKDF2 Iterations: {Config.PBKDF2_ITERATIONS:,}")
    print("\n🌐 Application URLs:")
    print(f"  → Local:  http://127.0.0.1:{Config.PORT}")
    print(f"  → LAN:    http://{lan_ip}:{Config.PORT}")
    print(f"  → API:    http://127.0.0.1:{Config.PORT}/api/health")
    print("=" * 50)
    
    # Run Flask server
    app.run(
        host=Config.HOST,
        port=Config.PORT,
        debug=Config.DEBUG
    )