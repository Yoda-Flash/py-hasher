import base64
import hashlib

from Crypto.Cipher import AES  # from pycryptodomex v-3.10.4
from Crypto.Random import get_random_bytes

class AES_GCM():
    def __init__(self):
        self.HASH_NAME = "SHA512"
        self.IV_LENGTH = 12
        self.ITERATION_COUNT = 65535
        self.KEY_LENGTH = 32
        self.SALT_LENGTH = 16
        self.TAG_LENGTH = 16


    def encrypt(self, password, plain_message):
        salt = get_random_bytes(self.SALT_LENGTH)
        iv = get_random_bytes(self.IV_LENGTH)

        secret = self.get_secret_key(password, salt)

        cipher = AES.new(secret, AES.MODE_GCM, iv)

        encrypted_message_byte, tag = cipher.encrypt_and_digest(
            plain_message.encode("utf-8")
        )
        cipher_byte = salt + iv + encrypted_message_byte + tag

        encoded_cipher_byte = base64.b64encode(cipher_byte)
        return bytes.decode(encoded_cipher_byte)


    def decrypt(self, password, cipher_message):
        decoded_cipher_byte = base64.b64decode(cipher_message)

        salt = decoded_cipher_byte[:self.SALT_LENGTH]
        iv = decoded_cipher_byte[self.SALT_LENGTH : (self.SALT_LENGTH + self.IV_LENGTH)]
        encrypted_message_byte = decoded_cipher_byte[
            (self.IV_LENGTH + self.SALT_LENGTH) : -self.TAG_LENGTH
        ]
        tag = decoded_cipher_byte[-self.TAG_LENGTH:]
        secret = self.get_secret_key(password, salt)
        cipher = AES.new(secret, AES.MODE_GCM, iv)

        decrypted_message_byte = cipher.decrypt_and_verify(encrypted_message_byte, tag)
        return decrypted_message_byte.decode("utf-8")


    def get_secret_key(self, password, salt):
        return hashlib.pbkdf2_hmac(
            self.HASH_NAME, password.encode(), salt, self.ITERATION_COUNT, self.KEY_LENGTH
        )

def main():
    aes_gcm = AES_GCM()
    outputFormat = "{:<25}:{}"
    # secret_key = "your_secure_key"
    # plain_text = "Your_plain_text"
    secret_key = input("Secret key: \n")
    plain_text = input("Plain text: \n")

    print("------ AES-GCM Encryption ------")
    cipher_text = aes_gcm.encrypt(secret_key, plain_text)
    print(outputFormat.format("encryption input", plain_text))
    print(outputFormat.format("encryption output", cipher_text))

    decrypted_text = aes_gcm.decrypt(secret_key, cipher_text)

    print("\n------ AES-GCM Decryption ------")
    print(outputFormat.format("decryption input", cipher_text))
    print(outputFormat.format("decryption output", decrypted_text))

if __name__ == "__main__":
    main()