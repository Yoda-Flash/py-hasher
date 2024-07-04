class SHA_256_Hasher():
    def __init__(self):
        pass

    def get_plain_message(self) -> str:
        message = input("Please enter the message you wish to hash: \n")
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
    def bit_to_hex(self, value) -> str:
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

    def chunker(self, bits, chunk_length=8):
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
        if length < 448:
            bits.append(1)
            bits = self.fill_zeros(bits, 448, "LE")
            bits += message_length
            return [bits]
        elif 448 <= length <= 512:
            bits.append(1)
            bits = self.fill_zeros(bits, 1024, "LE")
            bits[-64:] = message_length
            return self.chunker(bits, 512)
        else:
            bits.append(1)
            while (len(bits)+64) % 512 != 0:
                bits.append(0)
            bits += message_length
            return self.chunker(bits, 512)

    def is_true(self, x): return x == 1

    def if_ (self, i, y, z): return y if self.is_true(i) else z

    def and_(self, i, j): return self.if_(i, j, 0)
    def AND(self, i, j): return [self.and_(ia, ja) for ia, ja in zip(i, j)]

    def not_(self, i): return self.if_(i, 0, 1)
    def NOT(self, i): return [self.not_(x) for x in i]

    def xor(self, i, j): return self.if_(i, self.not_(j), j)
    def XOR(self, i, j): return [self.xor(ia, ja) for ia, ja in zip(i, j)]

    def xorxor(self, i, j, l): return self.xor(i, self.xor(j, l))
    def XORXOR(self, i, j, l): return [self.xorxor(ia, ja, la) for ia, ja, la, in zip(i, j, l)]

    def maj(self, i, j, k): return max([i, j,], key=[i, j, k].count)

    def rotr(self, x, n): return x[-n:] + x[:-n]
    def shr(self, x, n): return n * [0] + x[:-n]

    def add(self, i, j):
        length = len(i)
        sums = list(range(length))
        c = 0
        for x in range(length-1, -1, -1):
            sums[x] = self.xorxor(i[x], j[x], c)
            c = self.maj(i[x], j[x], c)
        return sums

    def sha256(self, message):
        h = ['0x6a09e667', '0xbb67ae85', '0x3c6ef372', '0xa54ff53a', '0x510e527f', '0x9b05688c', '0x1f83d9ab',
             '0x5be0cd19']

        k = ['0x428a2f98', '0x71374491', '0xb5c0fbcf', '0xe9b5dba5', '0x3956c25b', '0x59f111f1', '0x923f82a4',
             '0xab1c5ed5',
             '0xd807aa98', '0x12835b01', '0x243185be', '0x550c7dc3', '0x72be5d74', '0x80deb1fe', '0x9bdc06a7',
             '0xc19bf174',
             '0xe49b69c1', '0xefbe4786', '0x0fc19dc6', '0x240ca1cc', '0x2de92c6f', '0x4a7484aa', '0x5cb0a9dc',
             '0x76f988da',
             '0x983e5152', '0xa831c66d', '0xb00327c8', '0xbf597fc7', '0xc6e00bf3', '0xd5a79147', '0x06ca6351',
             '0x14292967',
             '0x27b70a85', '0x2e1b2138', '0x4d2c6dfc', '0x53380d13', '0x650a7354', '0x766a0abb', '0x81c2c92e',
             '0x92722c85',
             '0xa2bfe8a1', '0xa81a664b', '0xc24b8b70', '0xc76c51a3', '0xd192e819', '0xd6990624', '0xf40e3585',
             '0x106aa070',
             '0x19a4c116', '0x1e376c08', '0x2748774c', '0x34b0bcb5', '0x391c0cb3', '0x4ed8aa4a', '0x5b9cca4f',
             '0x682e6ff3',
             '0x748f82ee', '0x78a5636f', '0x84c87814', '0x8cc70208', '0x90befffa', '0xa4506ceb', '0xbef9a3f7',
             '0xc67178f2']

        k = self.initializer(k)
        h0, h1, h2, h3, h4, h5, h6, h7 = self.initializer(h)
        chunks = self.preprocess_message(message)
        for chunk in chunks:
            w = self.chunker(chunk, 32)
            for _ in range(48):
                w.append(32 * [0])
            for i in range(16, 64):
                s0 = self.XORXOR(self.rotr(w[i-15], 7), self.rotr(w[i-15], 18), self.shr(w[i-15], 3))
                s1 = self.XORXOR(self.rotr(w[i-2], 17), self.rotr(w[i-2], 19), self.shr(w[i-2], 10))
                w[i] = self.add(self.add(self.add(w[i-16], s0), w[i-7]), s1)
            a = h0
            b = h1
            c = h2
            d = h3
            e = h4
            f = h5
            g = h6
            h = h7
            for j in range(64):
                S1 = self.XORXOR(self.rotr(e, 6), self.rotr(e, 11), self.rotr(e, 25))
                ch = self.XOR(self.AND(e, f), self.AND(self.NOT(e), g))
                temp1 = self.add(self.add(self.add(self.add(h, S1), ch), k[j]), w[j])
                S0 = self.XORXOR(self.rotr(a, 2), self.rotr(a, 13), self.rotr(a, 22))
                m = self.XORXOR(self.AND(a, b), self.AND(a, c), self.AND(b, c))
                temp2 = self.add(S0, m)
                h = g
                g = f
                f = e
                e = self.add(d, temp1)
                d = c
                c = b
                b = a
                a = self.add(temp1, temp2)
            h0 = self.add(h0, a)
            h1 = self.add(h1, b)
            h2 = self.add(h2, c)
            h3 = self.add(h3, d)
            h4 = self.add(h4, e)
            h5 = self.add(h5, f)
            h6 = self.add(h6, g)
            h7 = self.add(h7, h)
        digest = ''
        for val in [h0, h1, h2, h3, h4, h5, h6, h7]:
            digest += self.bit_to_hex(val)
        return digest

def main():
    hasher = SHA_256_Hasher()
    message = hasher.get_plain_message()
    print(hasher.sha256(message))

if __name__ == "__main__":
    main()