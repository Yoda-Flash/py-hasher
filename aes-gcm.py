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

    print(f"Your key: {key}")
    if "e" in mode:
        message = input("Please input the message you would like to encrypt. \n").strip().encode("utf-8")
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

# key: \xd1\xae\xa4\xc2=\x08\x9d\xdf\xc6\x19\x1c\x8dw\xef1\xfe
# text: \x83A3\xff\xcb
# tag: u\xae\x86\nP\x91\xe6^\x9dn\x97\xd3v\xe7\xe5\xa1
# nonce:\xfd\xb3\xfd\xe5\xd9m\x08\xa4\nn\x14\x10\xcd\x04\x1f\x06