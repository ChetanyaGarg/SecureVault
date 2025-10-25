# 🔒 SecureVault

A professional, enterprise-grade file encryption and storage system built with Flask and military-grade AES-256 encryption.

## ✨ Features

### 🔐 Security Features
- **AES-256 Encryption**: Military-grade symmetric encryption
- **PBKDF2 Key Derivation**: 400,000 iterations with SHA-512 for password hashing
- **Password Validation**: Strong password requirements with complexity checks
- **File Size Limits**: Configurable maximum file size protection
- **Secure Filename Handling**: Protection against path traversal attacks
- **No Password Storage**: Passwords are never stored, only used for encryption

### 🚀 Professional Features
- **Modern UI**: Beautiful, responsive design with dark theme
- **File Management**: Upload, encrypt, and download files with metadata
- **API Endpoints**: RESTful API for programmatic access
- **Comprehensive Logging**: Detailed logging for security and debugging
- **Error Handling**: Graceful error handling with user-friendly messages
- **Configuration Management**: Environment-based configuration
- **Health Monitoring**: Built-in health check endpoints

### 📊 Monitoring & Analytics
- **File Statistics**: Track stored files and total size
- **Upload/Download Logging**: Audit trail for all operations
- **Performance Metrics**: Monitor system performance
- **Security Events**: Log security-related events

## 🛠️ Installation

### Prerequisites
- Python 3.8 or higher
- pip (Python package manager)

### Quick Start

1. **Clone or download the project**
   ```bash
   git clone https://github.com/ChetanyaGarg/SecureVault.git
   cd secure-file-storage
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Configure environment (optional)**
   ```bash
   cp config.env.example .env
   # Edit .env file with your settings
   ```

4. **Run the application**
   ```bash
   python app.py
   ```

5. **Access the application**
   - Open your browser to `http://localhost:8080`
   - Upload files and encrypt them with strong passwords

## ⚙️ Configuration

### Environment Variables

Create a `.env` file or set these environment variables:

```bash
# Security Settings
MAX_FILE_SIZE=104857600          # 100MB in bytes
MIN_PASSWORD_LENGTH=8            # Minimum password length
MAX_PASSWORD_LENGTH=128          # Maximum password length
PBKDF2_ITERATIONS=400000         # Key derivation iterations

# File Storage
UPLOAD_DIR=uploads               # Directory for encrypted files
ALLOWED_EXTENSIONS=              # Comma-separated list (empty = all allowed)

# Application Settings
SECRET_KEY=your-secret-key       # Flask secret key
DEBUG=False                      # Debug mode
HOST=0.0.0.0                    # Host to bind to
PORT=8080                       # Port to run on

# Logging
LOG_LEVEL=INFO                  # Logging level
LOG_FILE=app.log                # Log file path
```

### Security Configuration

For production deployment, consider these security settings:

```bash
# Production Security Settings
MAX_FILE_SIZE=52428800          # 50MB limit
MIN_PASSWORD_LENGTH=12          # Stronger passwords
PBKDF2_ITERATIONS=600000        # More iterations
DEBUG=False                     # Disable debug mode
LOG_LEVEL=WARNING               # Reduce log verbosity
```

## 🔧 API Reference

### Endpoints

#### `GET /`
Main application interface for file upload and management.

#### `POST /`
Upload and encrypt a file.
- **Form Data**:
  - `file`: The file to encrypt
  - `custom_name`: Name for the encrypted file
  - `password`: Encryption password

#### `GET /download/<filename>`
Download page for a specific encrypted file.

#### `POST /download/<filename>`
Decrypt and download a file.
- **Form Data**:
  - `password`: Decryption password

#### `GET /api/files`
Get list of all encrypted files.
- **Response**: JSON with file metadata

#### `GET /api/health`
Health check endpoint.
- **Response**: JSON with system status

### Example API Usage

```bash
# Get list of files
curl http://localhost:8080/api/files

# Health check
curl http://localhost:8080/api/health
```

## 🧪 Testing

Run the comprehensive test suite:

```bash
python test_app.py
```

The test suite covers:
- Encryption/decryption functionality
- Password validation
- File management utilities
- Security validations
- Error handling

## 🐳 Docker Deployment

### Dockerfile
```dockerfile
FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8080

CMD ["python", "app.py"]
```

### Docker Compose
```yaml
version: '3.8'
services:
  secure-storage:
    build: .
    ports:
      - "8080:8080"
    volumes:
      - ./uploads:/app/uploads
      - ./logs:/app/logs
    environment:
      - MAX_FILE_SIZE=104857600
      - DEBUG=False
    restart: unless-stopped
```

## 🔒 Security Best Practices

### Password Requirements
- Minimum 8 characters (configurable)
- Must contain uppercase and lowercase letters
- Must contain at least one digit
- Cannot be common weak passwords
- Maximum length limit to prevent DoS

### File Security
- All files encrypted with AES-256
- Unique salt for each file
- No metadata stored in plaintext
- Secure filename handling
- File size limits

### Application Security
- No password storage
- Comprehensive input validation
- Secure error handling
- Audit logging
- CSRF protection (Flask built-in)

## 📊 Monitoring

### Log Files
- `app.log`: Application logs
- Console output: Real-time monitoring

### Health Checks
- `/api/health`: System health status
- File system monitoring
- Memory usage tracking

### Security Events
- Failed login attempts
- File upload/download events
- Error conditions
- Configuration changes

## 🚀 Production Deployment

### Recommended Setup

1. **Use a production WSGI server**:
   ```bash
   pip install gunicorn
   gunicorn -w 4 -b 0.0.0.0:8080 app:app
   ```

2. **Set up reverse proxy** (Nginx):
   ```nginx
   server {
       listen 80;
       server_name your-domain.com;
       
       location / {
           proxy_pass http://127.0.0.1:8080;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
       }
   }
   ```

3. **Enable HTTPS** with SSL certificates

4. **Set up log rotation**:
   ```bash
   # /etc/logrotate.d/secure-storage
   /path/to/app.log {
       daily
       rotate 30
       compress
       delaycompress
       missingok
       notifempty
   }
   ```

5. **Configure firewall**:
   ```bash
   ufw allow 80/tcp
   ufw allow 443/tcp
   ufw deny 8080/tcp  # Block direct access
   ```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Create an issue in the repository
- Check the documentation
- Review the test cases for usage examples

## 🔄 Version History

### v2.0.0 (Current) - SecureVault
- Complete rewrite with professional architecture
- Enhanced security features
- Modern UI/UX design
- Comprehensive testing
- API endpoints
- Configuration management
- Production-ready deployment

### v1.0.0 (Original)
- Basic file encryption
- Simple web interface
- Core functionality

---

**Made with ❤️ by Chetanya**

*Secure your files with military-grade encryption*
