from pymd5 import md5, padding

class md5Ex(object):
	def __init__(self, data, signature, secret_len, append):
		self.data = data
		self.signature = signature
		self.secret_len = secret_len
		self.append = append
		self.hashB = md5()
		self.block_size = 64
		self._b2 = self.block_size*8

	def get_init_vec(self):
		print "0x"+self.signature[0:8].decode('hex')[::-1].encode('hex')
		print "0x"+self.signature[8:16].decode('hex')[::-1].encode('hex')
		print "0x"+self.signature[16:24].decode('hex')[::-1].encode('hex')
		print "0x"+self.signature[24:32].decode('hex')[::-1].encode('hex')

	def extend(self):
		msg_len = len(self.data) + self.secret_len
		pad = padding(msg_len * 8)		

		bits_msg = (msg_len + len(pad)) * 8

		self.hashB = md5(state=self.signature.decode("hex"), count=bits_msg)
		self.hashB.update(self.append)
		return self.getNewData()

	def __byter(self, byteVal):
		'''Helper function to return usable values for hash extension append data'''
		if byteVal < 0x20 or byteVal > 0x7e:
			return '\\x%02x' % (byteVal)
		else:
			return chr(byteVal)

	def getNewData(self):
		originalHashLength = bin((self.secret_len + len(self.data)) * 8)[2:].rjust(self.block_size, "0") + "0" * 56
		padData = ''.join(bin(ord(i))[2:].rjust(8, "0") for i in self.data) + "1"
		padData += "0" * (((self.block_size*7) - (len(padData)+(self.secret_len*8)-56) % self._b2) % self._b2) + originalHashLength 
		return ''.join([ self.__byter(int(padData[a:a+8],base=2)) for a in range(0,len(padData),8) ]) + self.append

	def hexdigest(self):
		return self.hashB.hexdigest()
		
	def hexdump(self):
		payload = self.data + self.pad() + self.append
		for b in range(0, len(payload), 16):
			lin = [c for c in payload[b : b + 16]]
			hxdat = ' '.join('%02X' % ord(c) for c in lin)
			pdat = ''.join((c if 32 <= ord(c) <= 126 else '.' )for c in lin)
			print('  %04x: %-48s %s' % (b, hxdat, pdat))
		print

	def getHex(self):
		payload = self.data + padding((len(self.data) + self.secret_len) * 8) + self.append
		return ''.join('%02X' % ord(c) for c in payload)

	def digest(self):
		return self.hashB.digest()

