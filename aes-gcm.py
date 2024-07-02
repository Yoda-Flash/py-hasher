from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

class GCM:

    def encrypt(self, header, key, data):
        cipher = AES.new(key, AES.MODE_GCM)
        cipher.update(header)

        cipher_text, tag = cipher.encrypt_and_digest(data)
        nonce = cipher.nonce
        print(f"Cipher text: {cipher_text}")
        print(f"Cipher tag: {tag}")
        print(f"Cipher nonce: {nonce}")

        return cipher_text, tag, nonce

    def decrypt(self, header, key, nonce, cipher_text, tag):
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        cipher.update(header)

        plain_text = cipher.decrypt_and_verify(cipher_text, tag).decode("utf-8")
        print(f"Your text: {plain_text}")
        return plain_text

def main():
    gcm = GCM()
    header = b"header"
    mode = input("Do you wish to encrypt or decrypt? If encrypt, type 'e', if decrypt, type 'd' \n").lower()
    has_key = input("Do you have a key? If so, please input it. If not, please hit enter. \n")
    nonce = None
    cipher_text = None
    tag = None

    if has_key != "":
        key = has_key
    else:
        key = get_random_bytes(16)
    print(type(key))
    print(f"Your key: {key}")
    if "e" in mode:
        message = input('Please input the message you would like to encrypt. \n').strip().encode("utf-8")
        cipher_text, tag, nonce = gcm.encrypt(header, key, message)
    elif "d" in mode:
        if nonce is None:
            nonce = input("Please input the nonce. \n").strip()
            nonce = bytes(nonce, "utf-8")
        if cipher_text is None:
            cipher_text = input("Please input the encrypted text. \n").strip()
        if tag is None:
            tag = input("Please input the tag. \n").strip()

        gcm.decrypt(header, key, nonce, cipher_text, tag)

if __name__ == "__main__":
    main()

# key:  b'!\xac\xd2\xd8Ms9@\x95\xc9Ud\x1c\x95[\xf9'
# text: b'1\x83\xb2\xef\xd0'
# tag: b'\x00\xb6?\x9c\xea\x9cx\x84KW\xa4\r\x19z\xf0C'
# nonce: b'\xbd\x9b\xa40nTJ\xed\x87\x10e\xf7R\x0f\xb5&'