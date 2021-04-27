# Copyright (C) 2014 by Stephen Bradshaw
#
# SHA1 and SHA2 generation routines from SlowSha https://code.google.com/p/slowsha/
# which is: Copyright (C) 2011 by Stefano Palazzo
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
# THE SOFTWARE.


__version__ = "0.1"


from re import match
from math import ceil

class sha1Ex (object):

    _h0, _h1, _h2, _h3, _h4, = (
        0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0)

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
        originalHashLength = bin((self.secret_len + len(self.data)) * 8)[2:].rjust(64, "0")    
        padData = ''.join(bin(ord(i))[2:].rjust(8, "0") for i in self.data) + "1"
        padData += "0" * (((64*7) - (len(padData)+(self.secret_len*8)) % 512) % 512) + originalHashLength
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

        lrot = lambda x, n: (x << n) | (x >> (32 - n))
        w = []

        for j in xrange(len(chunk) // 32):
            w.append(int(chunk[j * 32:j * 32 + 32], 2))

        for i in xrange(16, 80):
            w.append(lrot(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1)
                & 0xffffffff)

        a = self._h0
        b = self._h1
        c = self._h2
        d = self._h3
        e = self._h4

        for i in xrange(80):

            if i <= i <= 19:
                f, k = d ^ (b & (c ^ d)), 0x5a827999
            elif 20 <= i <= 39:
                f, k = b ^ c ^ d, 0x6ed9eba1
            elif 40 <= i <= 59:
                f, k = (b & c) | (d & (b | c)), 0x8f1bbcdc
            elif 60 <= i <= 79:
                f, k = b ^ c ^ d, 0xca62c1d6

            temp = lrot(a, 5) + f + e + k + w[i] & 0xffffffff
            a, b, c, d, e = temp, a, lrot(b, 30), c, d

        self._h0 = (self._h0 + a) & 0xffffffff
        self._h1 = (self._h1 + b) & 0xffffffff
        self._h2 = (self._h2 + c) & 0xffffffff
        self._h3 = (self._h3 + d) & 0xffffffff
        self._h4 = (self._h4 + e) & 0xffffffff
