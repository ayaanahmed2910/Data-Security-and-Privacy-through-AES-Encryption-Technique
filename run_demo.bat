@echo off
REM AES Encryption System Demo Script for Windows
REM This script demonstrates the AES encryption system functionality

echo ========================================
echo  AES Encryption System Demo
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo ❌ Python is not installed or not in PATH
    echo Please install Python 3.7+ and try again
    pause
    exit /b 1
)

REM Install dependencies if requirements.txt exists
if exist requirements.txt (
    echo 📦 Installing dependencies...
    pip install -r requirements.txt
    if %errorlevel% neq 0 (
        echo ❌ Failed to install dependencies
        pause
        exit /b 1
    )
    echo ✅ Dependencies installed successfully
    echo.
)

REM Run the main demonstration
echo 🔐 Running AES Encryption Demo...
python aes_encryption.py
echo.
echo Press any key to continue...
pause >nul

REM Run the test suite
echo 🧪 Running Test Suite...
python test_encryption.py
echo.
echo Press any key to continue...
pause >nul

REM Show CLI interface help
echo 💻 CLI Interface Help:
echo.
python cli_interface.py --help
echo.
echo Press any key to continue...
pause >nul

REM Generate a sample key
echo 🔑 Generating Sample Key:
echo.
python cli_interface.py generate-key
echo.
echo Press any key to continue...
pause >nul

REM Show system information
echo 📋 System Information:
echo.
python cli_interface.py info
echo.

echo ========================================
echo Demo completed successfully!
echo ========================================
echo.
echo Files created:
echo - aes_encryption.py (Main implementation)
echo - web_interface.html (Web interface)
echo - cli_interface.py (Command line tool)
echo - test_encryption.py (Test suite)
echo - README.md (Documentation)
echo.
echo To use the web interface:
echo 1. Open web_interface.html in your browser
echo 2. Or run: python -m http.server 8000
echo 3. Visit: http://localhost:8000/web_interface.html
echo.
echo Press any key to exit...
pause >nul
