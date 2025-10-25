#!/bin/bash

# SecureVault Deployment Script
# This script helps you deploy the SecureVault application

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check Python version
check_python() {
    if command_exists python3; then
        PYTHON_VERSION=$(python3 -c 'import sys; print(".".join(map(str, sys.version_info[:2])))')
        if python3 -c 'import sys; exit(0 if sys.version_info >= (3, 8) else 1)'; then
            print_success "Python $PYTHON_VERSION found"
            return 0
        else
            print_error "Python 3.8+ required, found $PYTHON_VERSION"
            return 1
        fi
    else
        print_error "Python 3 not found"
        return 1
    fi
}

# Function to install dependencies
install_dependencies() {
    print_status "Installing Python dependencies..."
    if [ -f "requirements.txt" ]; then
        pip3 install -r requirements.txt
        print_success "Dependencies installed successfully"
    else
        print_error "requirements.txt not found"
        return 1
    fi
}

# Function to create necessary directories
create_directories() {
    print_status "Creating necessary directories..."
    mkdir -p uploads logs
    print_success "Directories created"
}

# Function to setup environment
setup_environment() {
    if [ ! -f ".env" ]; then
        print_status "Creating .env file from template..."
        if [ -f "config.env.example" ]; then
            cp config.env.example .env
            print_warning "Please edit .env file with your configuration"
        else
            print_warning "No .env template found, using defaults"
        fi
    else
        print_success ".env file already exists"
    fi
}

# Function to run tests
run_tests() {
    if [ -f "test_app.py" ]; then
        print_status "Running tests..."
        python3 test_app.py
        print_success "Tests completed"
    else
        print_warning "No test file found"
    fi
}

# Function to start application
start_application() {
    print_status "Starting Secure File Storage Application..."
    print_status "The application will be available at:"
    print_status "  - Local:  http://127.0.0.1:8080"
    print_status "  - LAN:    http://$(hostname -I | awk '{print $1}'):8080"
    print_status ""
    print_status "Press Ctrl+C to stop the application"
    print_status ""
    
    python3 app.py
}

# Function to start with Docker
start_docker() {
    if command_exists docker && command_exists docker-compose; then
        print_status "Starting with Docker Compose..."
        docker-compose up --build
    else
        print_error "Docker or Docker Compose not found"
        return 1
    fi
}

# Function to show help
show_help() {
    echo "SecureVault Deployment Script"
    echo ""
    echo "Usage: $0 [OPTION]"
    echo ""
    echo "Options:"
    echo "  install     Install dependencies and setup environment"
    echo "  test        Run test suite"
    echo "  start       Start the application"
    echo "  docker      Start with Docker Compose"
    echo "  full        Install, test, and start (default)"
    echo "  help        Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0              # Full setup and start"
    echo "  $0 install      # Install dependencies only"
    echo "  $0 docker       # Start with Docker"
    echo ""
}

# Main function
main() {
    case "${1:-full}" in
        "install")
            print_status "Installing SecureVault..."
            check_python || exit 1
            install_dependencies || exit 1
            create_directories
            setup_environment
            print_success "Installation completed!"
            ;;
        "test")
            print_status "Running tests..."
            run_tests
            ;;
        "start")
            print_status "Starting application..."
            start_application
            ;;
        "docker")
            print_status "Starting with Docker..."
            start_docker
            ;;
        "full")
            print_status "Full setup and start..."
            check_python || exit 1
            install_dependencies || exit 1
            create_directories
            setup_environment
            run_tests
            start_application
            ;;
        "help"|"-h"|"--help")
            show_help
            ;;
        *)
            print_error "Unknown option: $1"
            show_help
            exit 1
            ;;
    esac
}

# Run main function with all arguments
main "$@"
