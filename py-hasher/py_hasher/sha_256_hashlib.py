import hashlib

hasher = hashlib.sha256()
plainMessage = input("Please enter the message you wish to has: \n").strip()
hasher.update(plainMessage.encode('utf-8'))
print(hasher.hexdigest())