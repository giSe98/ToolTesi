from re import match
from math import ceil

class sha256Ex (object):

    _h0, _h1, _h2, _h3, _h4, _h5, _h6, _h7 = (
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19)

    block_size = 64

    def __init__(self, data, signature, secret_len, append):
        self._b1 = self.block_size/8
        self._b2 = self.block_size*8
        self.data = data
        self.signature = signature
        self.secret_len = secret_len
        self.append = append
        self.message = append

    def extend(self):
        self.setIV(self.signature)        
        
        extendLength = self.getExtendLength()        

        while len(self.message) > self.block_size:
            self.handle(''.join([bin(ord(a))[2:].rjust(8, "0") for a in self.message[:self.block_size]]))
            self.message = self.message[self.block_size:]

        self.message = self.getBinaryPad(self.message, extendLength)        

        for i in range(len(self.message) // self._b2):
            self.handle(self.message[i * self._b2:i * self._b2 + self._b2])

        return self.padding()

    def hexdigest(self):
        return ''.join( [ (('%0' + str(self._b1) + 'x') % (a)) for a in self.digest()])


    def digest(self):
        return [self.__getattribute__(a) for a in dir(self) if match('^_h\d+$', a)]


    def setIV(self, signature):
        c = 0
        hashVals = [ int(signature[a:a+self._b1],base=16) for a in range(0,len(signature), self._b1) ]
        for hv in [ a for a in dir(self) if match('^_h\d+$', a) ]:
            self.__setattr__(hv, hashVals[c])        
            c+=1

    def __byter(self, byteVal):
        '''Helper function to return usable values for hash extension append data'''
        if byteVal < 0x20 or byteVal > 0x7e:
            return '\\x%02x' % (byteVal)
        else:    
            return chr(byteVal)


    def binToByte(self, binary):
        return ''.join([ chr(int(binary[a:a+8],base=2)) for a in range(0,len(binary),8) ])

    def getHex(self):
        originalHashLength = bin((self.secret_len + len(self.data)) * 8)[2:].rjust(self.block_size, "0")    
        padData = ''.join(bin(ord(i))[2:].rjust(8, "0") for i in self.data) + "1"
        padData += "0" * (((self.block_size*7) - (len(padData)+(self.secret_len*8)) % self._b2) % self._b2) + originalHashLength 
        return self.data.encode('hex') + self.binToByte(padData).encode('hex') + self.append.encode('hex')

    def getExtendLength(self):
        # binary length (self.secret_len + len(self.data) + size of binarysize+1) rounded to a multiple of blockSize + length of appended data
        originalHashLength = int(ceil((self.secret_len+len(self.data)+self._b1+1)/float(self.block_size)) * self.block_size) 
        newHashLength = originalHashLength + len(self.append) 
        return bin(newHashLength * 8)[2:].rjust(self.block_size, "0")


    def padding(self):
        originalHashLength = bin((self.secret_len + len(self.data)) * 8)[2:].rjust(self.block_size, "0")    
        padData = ''.join(bin(ord(i))[2:].rjust(8, "0") for i in self.data) + "1"
        padData += "0" * (((self.block_size*7) - (len(padData)+(self.secret_len*8)) % self._b2) % self._b2) + originalHashLength 
        return ''.join([ self.__byter(int(padData[a:a+8],base=2)) for a in range(0,len(padData),8) ]) + self.append

    def getBinaryPad(self, message, length):
        message = ''.join(bin(ord(i))[2:].rjust(8, "0") for i in message) + "1"    
        message += "0" * (((self.block_size*7) - len(message) % self._b2) % self._b2) + length
        return message


    def handle(self, chunk):
        rrot = lambda x, n: (x >> n) | (x << (32 - n))
        w = []

        k = [
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
            0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
            0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
            0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
            0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
            0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
            0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
            0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
            0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

        for j in xrange(len(chunk) // 32):
            w.append(int(chunk[j * 32:j * 32 + 32], 2))

        for i in xrange(16, 64):
            s0 = rrot(w[i - 15], 7) ^ rrot(w[i - 15], 18) ^ (w[i - 15] >> 3)
            s1 = rrot(w[i - 2], 17) ^ rrot(w[i - 2], 19) ^ (w[i - 2] >> 10)
            w.append((w[i - 16] + s0 + w[i - 7] + s1) & 0xffffffff)

        a = self._h0
        b = self._h1
        c = self._h2
        d = self._h3
        e = self._h4
        f = self._h5
        g = self._h6
        h = self._h7

        for i in xrange(64):
            s0 = rrot(a, 2) ^ rrot(a, 13) ^ rrot(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            t2 = s0 + maj
            s1 = rrot(e, 6) ^ rrot(e, 11) ^ rrot(e, 25)
            ch = (e & f) ^ ((~ e) & g)
            t1 = h + s1 + ch + k[i] + w[i]

            h = g
            g = f
            f = e
            e = (d + t1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xffffffff

        self._h0 = (self._h0 + a) & 0xffffffff
        self._h1 = (self._h1 + b) & 0xffffffff
        self._h2 = (self._h2 + c) & 0xffffffff
        self._h3 = (self._h3 + d) & 0xffffffff
        self._h4 = (self._h4 + e) & 0xffffffff
        self._h5 = (self._h5 + f) & 0xffffffff
        self._h6 = (self._h6 + g) & 0xffffffff
        self._h7 = (self._h7 + h) & 0xffffffff
