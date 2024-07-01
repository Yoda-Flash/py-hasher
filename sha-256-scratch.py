class Sha256Hasher():
    def __init__(self):
        pass

    def get_plain_message(self) -> str:
        message = input("Please enter the message you wish to hash: \n").strip()
        return message
    def translate(self, message: str) -> list[int]:
        charcodes = [ord(c) for c in message]
        bytes = []
        for c in charcodes:
            bytes.append(bin(c)[2:].zfill(8))
        bits = []
        for byte in bytes:
            for bit in byte:
                bits.append(int(bit))
        return bits

    # Base 2 to Base 16
    def bit_to_hex(self, value: list[int]) -> str:
        value = "".join([str(x) for x in value])
        binaries = []
        for d in range(0, len(value), 4):
            binaries.append("0b" + value[d:d+4])
        hexes = ''
        for b in binaries:
            hexes += hex(int(b, 2))[2:]
        return hexes

    def fill_zeros(self, bits, length=8, endian="LE"):
        l = len(bits)
        if endian == "LE":
            for i in range(l, length):
                bits.append(0)
        else:
            while l < length:
                bits.insert(0, 0)
                l = len(bits)
        return bits

    def chunker(self, bits, chunk_length=8) -> list:
        chunked = []
        for b in range(0, len(bits), chunk_length):
            chunked.append(bits[b:b+chunk_length])
        return chunked

    def initializer(self, values):
        binaries = [bin(int(v, 16))[2:] for v in values]
        words = []
        for binary in binaries:
            word = []
            for b in binary:
                word.append(int(b))
            words.append(self.fill_zeros(word, 32, "BE"))
        return words

    def preprocess_message(self, message):
        bits = self.translate(message)
        length = len(bits)
        message_length = [int(b) for b in bin(length)[2:].zfill(64)]