# Instagram Password Encryptor

A Python implementation of Instagram's password encryption scheme (PWD_INSTAGRAM:4).

## Description

This script implements the hybrid encryption approach used by Instagram for secure password transmission during login:
- **AES-256-GCM** for encrypting the password
- **RSA-2048** for encrypting the AES session key

## Installation

```bash
pip install pycryptodome requests
```

## Usage

```python
from instagram_encryptor import InstagramPasswordEncryptor

encryptor = InstagramPasswordEncryptor()
encrypted_password = encryptor.password_encrypt("your_password")
print(encrypted_password)
```

Output format: `#PWD_INSTAGRAM:4:{timestamp}:{base64_payload}`

## How It Works

1. Fetches current public encryption keys from Instagram's API
2. Generates random AES-256 session key and IV
3. Encrypts the session key with RSA
4. Encrypts the password with AES-GCM
5. Combines everything into Instagram's required format

## Requirements

- Python 3.7+
- pycryptodome
- requests

## License

MIT

## Disclaimer

For educational purposes only. Use responsibly and comply with Instagram's Terms of Service.
