"""
Instagram Password Encryption Reference

This script implements the specific encryption scheme used by Instagram login (PWD_INSTAGRAM:4).
It uses a hybrid encryption approach:
1.  AES-256-GCM: Used to encrypt the actual password.
2.  RSA-2048: Used to encrypt the random AES session key.

The result is a formatted string containing the version, key ID, IV, encrypted AES key, and encrypted password.
"""

import base64
import time
import requests

try:
    # Standard import for pycryptodome
    from Crypto.Cipher import AES, PKCS1_v1_5
    from Crypto.PublicKey import RSA
    from Crypto.Random import get_random_bytes
except ImportError:
    # Alternative import (if installed as cryptodome)
    from Cryptodome.Cipher import AES, PKCS1_v1_5
    from Cryptodome.PublicKey import RSA
    from Cryptodome.Random import get_random_bytes


class InstagramPasswordEncryptor:
    def __init__(self):
        # Session to handle HTTP requests
        self.session = requests.Session()
        # Essential headers to ensure the API returns the keys
        self.session.headers.update({
            'User-Agent': 'Instagram 275.0.0.27.98 Android (33/13; 420dpi; 1080x2400; Google/google; Pixel 7; panther; tensor; en_US; 458229237)',
            'X-IG-App-ID': '567067343352427',  # Valid App ID
            'Accept-Language': 'en-US',
        })

    def password_encrypt(self, password: str) -> str:  # Encrypts the password for Instagram login. Format: #PWD_INSTAGRAM:4:{timestamp}:{payload}

        # Keys rotate, so we must fetch the latest one to ensure the server can decrypt it.
        publickeyid, publickey = self.password_publickeys()
        

        # A random 32-byte key for AES-256 encryption
        session_key = get_random_bytes(32)
        # A random 12-byte Initialization Vector (IV) for GCM mode
        iv = get_random_bytes(12)
        # Current timestamp (used as authentication data in GCM)
        timestamp = str(int(time.time()))

        # The key comes as a base64 encoded PEM string
        decoded_publickey = base64.b64decode(publickey.encode())
        recipient_key = RSA.import_key(decoded_publickey)

        # This allows the server (who has the private RSA key) to recover the AES key
        cipher_rsa = PKCS1_v1_5.new(recipient_key)
        rsa_encrypted = cipher_rsa.encrypt(session_key)


        # GCM provides both encryption (privacy) and authentication (integrity).
        cipher_aes = AES.new(session_key, AES.MODE_GCM, iv)
        # We verify the timestamp as "Associated Data" to prevent replay attacks
        cipher_aes.update(timestamp.encode())
        aes_encrypted, tag = cipher_aes.encrypt_and_digest(password.encode("utf8"))


        # Structure:
        # [1 byte: Version=1]
        # [1 byte: Public Key ID]
        # [12 bytes: IV]
        # [2 bytes: Length of RSA encrypted key (little-endian)]
        # [N bytes: RSA Encrypted AES Key]
        # [16 bytes: GCM Auth Tag]
        # [N bytes: AES Encrypted Password]
        
        size_buffer = len(rsa_encrypted).to_bytes(2, byteorder="little")
        
        payload = base64.b64encode(
            b"".join(
                [
                    b"\x01",                                 # Version
                    publickeyid.to_bytes(1, byteorder="big"),# Key ID
                    iv,                                      # IV
                    size_buffer,                             # Key Length
                    rsa_encrypted,                           # Encrypted Key
                    tag,                                     # Auth Tag
                    aes_encrypted,                           # Encrypted Data
                ]
            )
        )
        
        # 7. Format the final string
        return f"#PWD_INSTAGRAM:4:{timestamp}:{payload.decode()}"

    def password_publickeys(self):
        """
        Fetches the current encryption keys from Instagram's QE sync endpoint.
        These keys are returned in the response headers.
        """
        # The qe/sync endpoint is a reliable source for these keys
        resp = self.session.get("https://i.instagram.com/api/v1/qe/sync/")
        
        # Extract keys from headers
        # 'ig-set-password-encryption-key-id': The ID of the key (used in payload)
        # 'ig-set-password-encryption-pub-key': The base64 PEM public key
        publickeyid = int(resp.headers.get("ig-set-password-encryption-key-id"))
        publickey = resp.headers.get("ig-set-password-encryption-pub-key")
        
        return publickeyid, publickey


if __name__ == "__main__":
    # Example Usage
    encryptor = InstagramPasswordEncryptor()
    try:
        encrypted_pass = encryptor.password_encrypt("noahhsec")
        print("Encrypted Password String:")
        print(encrypted_pass)
    except Exception as e:
        print(f"Error: {e}")
