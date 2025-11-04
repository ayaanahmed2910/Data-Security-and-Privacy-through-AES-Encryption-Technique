from flask import Flask, request, jsonify, render_template_string
from aes_encryption import AESEncryption
import json

app = Flask(__name__)

# HTML template for the web interface
HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AES Encryption System - Real-Time Encryption</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            line-height: 1.6;
            color: #333;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }

        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }

        .header {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }

        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }

        .header p {
            font-size: 1.2em;
            opacity: 0.9;
        }

        .main-content {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 30px;
            padding: 30px;
        }

        .section {
            background: #f8f9fa;
            border-radius: 10px;
            padding: 25px;
            border-left: 5px solid #667eea;
        }

        .section h2 {
            color: #2c3e50;
            margin-bottom: 20px;
            font-size: 1.5em;
        }

        .form-group {
            margin-bottom: 20px;
        }

        label {
            display: block;
            margin-bottom: 8px;
            font-weight: 600;
            color: #555;
        }

        input, textarea {
            width: 100%;
            padding: 12px;
            border: 2px solid #ddd;
            border-radius: 8px;
            font-size: 14px;
            transition: border-color 0.3s ease;
        }

        input:focus, textarea:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }

        textarea {
            min-height: 150px;
            resize: vertical;
        }

        .btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 12px 30px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 16px;
            font-weight: 600;
            transition: transform 0.2s ease, box-shadow 0.2s ease;
            width: 100%;
        }

        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.3);
        }

        .btn:active {
            transform: translateY(0);
        }

        .result {
            background: #e8f5e8;
            border: 2px solid #4caf50;
            border-radius: 8px;
            padding: 15px;
            margin-top: 20px;
            display: none;
        }

        .result.error {
            background: #ffebee;
            border-color: #f44336;
        }

        .result.show {
            display: block;
        }

        .decrypted-display {
            background: #f8f9fa;
            border: 3px solid #28a745;
            border-radius: 10px;
            padding: 20px;
            margin-top: 20px;
            display: none;
            box-shadow: 0 4px 6px rgba(40, 167, 69, 0.1);
        }

        .decrypted-display.show {
            display: block;
        }

        .decrypted-display h3 {
            color: #28a745;
            margin-bottom: 15px;
            font-size: 1.3em;
            text-align: center;
        }

        .decrypted-content {
            background: white;
            border: 2px solid #e9ecef;
            border-radius: 8px;
            padding: 15px;
            font-family: 'Courier New', monospace;
            font-size: 14px;
            line-height: 1.5;
            white-space: pre-wrap;
            word-wrap: break-word;
            min-height: 100px;
            max-height: 300px;
            overflow-y: auto;
        }

        .copy-btn {
            background: #28a745;
            color: white;
            border: none;
            padding: 8px 16px;
            border-radius: 5px;
            cursor: pointer;
            font-size: 12px;
            margin-top: 10px;
            transition: background-color 0.3s ease;
        }

        .copy-btn:hover {
            background: #218838;
        }

        .features {
            background: #2c3e50;
            color: white;
            padding: 30px;
            text-align: center;
        }

        .features h2 {
            margin-bottom: 20px;
            font-size: 2em;
        }

        .features-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-top: 20px;
        }

        .feature {
            background: rgba(255,255,255,0.1);
            padding: 20px;
            border-radius: 10px;
            text-align: center;
        }

        .feature h3 {
            margin-bottom: 10px;
            color: #667eea;
        }

        .security-info {
            background: #fff3cd;
            border: 2px solid #ffc107;
            border-radius: 8px;
            padding: 15px;
            margin-top: 15px;
        }

        .security-info h4 {
            color: #856404;
            margin-bottom: 10px;
        }

        @media (max-width: 768px) {
            .main-content {
                grid-template-columns: 1fr;
            }

            .header h1 {
                font-size: 2em;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔐 AES Encryption System</h1>
            <p>Real-Time Data Security and Privacy Protection</p>
        </div>

        <div class="main-content">
            <div class="section">
                <h2>🔒 Encrypt Data</h2>
                <form id="encryptForm">
                    <div class="form-group">
                        <label for="encryptPassword">Encryption Password:</label>
                        <input type="password" id="encryptPassword" placeholder="Enter strong password" required>
                    </div>

                    <div class="form-group">
                        <label for="plaintext">Data to Encrypt:</label>
                        <textarea id="plaintext" placeholder="Enter sensitive data here..." required></textarea>
                    </div>

                    <button type="submit" class="btn">Encrypt Data</button>
                </form>

                <div id="encryptResult" class="result"></div>
            </div>

            <div class="section">
                <h2>🔓 Decrypt Data</h2>
                <form id="decryptForm">
                    <div class="form-group">
                        <label for="decryptPassword">Decryption Password:</label>
                        <input type="password" id="decryptPassword" placeholder="Enter password" required>
                    </div>

                    <div class="form-group">
                        <label for="encryptedData">Encrypted Data:</label>
                        <textarea id="encryptedData" placeholder="Paste encrypted data here..." required></textarea>
                    </div>

                    <button type="submit" class="btn">Decrypt Data</button>
                </form>

                <div id="decryptResult" class="result"></div>

                <div id="decryptedDisplay" class="decrypted-display">
                    <h3>🔓 Decrypted Plain Text</h3>
                    <div id="decryptedContent" class="decrypted-content">Your decrypted data will appear here...</div>
                    <button id="copyDecryptedBtn" class="copy-btn">📋 Copy Decrypted Data</button>
                </div>
            </div>
        </div>

        <div class="features">
            <h2>Security Features</h2>
            <div class="features-grid">
                <div class="feature">
                    <h3>🔐 AES-256</h3>
                    <p>Military-grade encryption algorithm providing maximum security</p>
                </div>
                <div class="feature">
                    <h3>🛡️ PBKDF2</h3>
                    <p>Secure key derivation with 100,000 iterations for password protection</p>
                </div>
                <div class="feature">
                    <h3>🔄 CBC Mode</h3>
                    <p>Cipher Block Chaining mode prevents pattern recognition attacks</p>
                </div>
                <div class="feature">
                    <h3>🔑 Random IV</h3>
                    <p>Unique initialization vector for each encryption operation</p>
                </div>
                <div class="feature">
                    <h3>📦 PKCS7 Padding</h3>
                    <p>Secure padding ensures data integrity during encryption</p>
                </div>
                <div class="feature">
                    <h3>🛠️ Base64 Encoding</h3>
                    <p>Safe encoding for data transmission and storage</p>
                </div>
            </div>
        </div>

        <div class="section" style="margin: 30px; border-left-color: #28a745;">
            <h2 style="color: #28a745;">📋 Sample Data for Testing</h2>
            <div class="security-info">
                <h4>🔒 Try this sample encrypted data:</h4>
                <p><strong>Password:</strong> <code>MySecurePassword123!</code></p>
                <p><strong>Encrypted Data:</strong></p>
                <textarea readonly id="sampleData" style="background: #f8f9fa; font-size: 12px; height: 100px;"></textarea>
            </div>
        </div>
    </div>

    <script>
        document.getElementById('encryptForm').addEventListener('submit', function(e) {
            e.preventDefault();

            const password = document.getElementById('encryptPassword').value;
            const plaintext = document.getElementById('plaintext').value;

            if (!password || !plaintext) {
                showResult('encryptResult', 'Please fill in all fields', 'error');
                return;
            }

            fetch('/encrypt', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify({ password: password, data: plaintext }),
            })
            .then(response => response.json())
            .then(data => {
                if (data.error) {
                    showResult('encryptResult', data.error, 'error');
                } else {
                    const resultText = `Encrypted Data:
{
    "ciphertext": "${data.ciphertext}",
    "iv": "${data.iv}",
    "salt": "${data.salt}"
}

Copy this data to use for decryption.`;
                    showResult('encryptResult', resultText);
                }
            })
            .catch(error => {
                showResult('encryptResult', 'Encryption failed: ' + error.message, 'error');
            });
        });

        document.getElementById('decryptForm').addEventListener('submit', function(e) {
            e.preventDefault();

            const password = document.getElementById('decryptPassword').value;
            const encryptedText = document.getElementById('encryptedData').value;

            if (!password || !encryptedText) {
                showResult('decryptResult', 'Please fill in all fields', 'error');
                return;
            }

            try {
                const encryptedData = JSON.parse(encryptedText);

                fetch('/decrypt', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({ password: password, ...encryptedData }),
                })
                .then(response => response.json())
                .then(data => {
                    if (data.error) {
                        showResult('decryptResult', data.error, 'error');
                    } else {
                        showDecryptedData(data.decrypted);
                        showResult('decryptResult', '✅ Decryption successful! See decrypted data below.');
                    }
                })
                .catch(error => {
                    showResult('decryptResult', 'Decryption failed: ' + error.message, 'error');
                });
            } catch (error) {
                showResult('decryptResult', 'Invalid encrypted data format', 'error');
            }
        });

        document.getElementById('copyDecryptedBtn').addEventListener('click', function() {
            const decryptedContent = document.getElementById('decryptedContent').textContent;

            if (navigator.clipboard && window.isSecureContext) {
                navigator.clipboard.writeText(decryptedContent).then(function() {
                    showResult('decryptResult', '✅ Decrypted data copied to clipboard!');
                }).catch(function(err) {
                    fallbackCopyTextToClipboard(decryptedContent);
                });
            } else {
                fallbackCopyTextToClipboard(decryptedContent);
            }
        });

        function fallbackCopyTextToClipboard(text) {
            const textArea = document.createElement("textarea");
            textArea.value = text;
            textArea.style.top = "0";
            textArea.style.left = "0";
            textArea.style.position = "fixed";
            document.body.appendChild(textArea);
            textArea.focus();
            textArea.select();

            try {
                const successful = document.execCommand('copy');
                if (successful) {
                    showResult('decryptResult', '✅ Decrypted data copied to clipboard!');
                } else {
                    showResult('decryptResult', '❌ Failed to copy data to clipboard', 'error');
                }
            } catch (err) {
                showResult('decryptResult', '❌ Failed to copy data to clipboard', 'error');
            }

            document.body.removeChild(textArea);
        }

        function showDecryptedData(decryptedText) {
            const display = document.getElementById('decryptedDisplay');
            const content = document.getElementById('decryptedContent');

            content.textContent = decryptedText;
            display.classList.add('show');
        }

        function showResult(elementId, message, type = 'success') {
            const element = document.getElementById(elementId);
            element.textContent = message;
            element.className = `result ${type} show`;
        }

        // Load sample encrypted data on page load
        document.addEventListener('DOMContentLoaded', function() {
            fetch('/sample')
            .then(response => response.json())
            .then(data => {
                document.getElementById('sampleData').value = JSON.stringify(data, null, 2);
            });
        });
    </script>
</body>
</html>
"""

@app.route('/')
def index():
    return render_template_string(HTML_TEMPLATE)

@app.route('/encrypt', methods=['POST'])
def encrypt():
    try:
        data = request.get_json()
        password = data.get('password')
        plaintext = data.get('data')

        if not password or not plaintext:
            return jsonify({'error': 'Password and data are required'}), 400

        aes = AESEncryption(password=password)
        encrypted = aes.encrypt(plaintext)

        return jsonify(encrypted)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        data = request.get_json()
        password = data.get('password')
        ciphertext = data.get('ciphertext')
        iv = data.get('iv')
        salt = data.get('salt')

        if not password or not ciphertext or not iv or not salt:
            return jsonify({'error': 'Password, ciphertext, iv, and salt are required'}), 400

        aes = AESEncryption(password=password)
        decrypted = aes.decrypt({
            'ciphertext': ciphertext,
            'iv': iv,
            'salt': salt
        })

        return jsonify({'decrypted': decrypted})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/sample')
def sample():
    # Generate sample encrypted data
    aes = AESEncryption(password="MySecurePassword123!")
    sample_data = {
        "user_id": "12345",
        "email": "user@example.com",
        "credit_card": "4532-1234-5678-9012",
        "personal_info": {
            "name": "John Doe",
            "address": "123 Main St, City, State 12345",
            "phone": "+1-555-0123"
        }
    }
    encrypted = aes.encrypt(json.dumps(sample_data, indent=2))
    return jsonify(encrypted)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
