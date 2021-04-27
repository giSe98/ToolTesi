#MD5 TEST COMPLETE
import md5Ex

data = "data"
secret_len = 6
append = "append"
signature = "6036708eba0d11f6ef52ad44e8b74d5b"

h = md5Ex.md5Ex(data, signature, secret_len, append)
newData = h.extend()
newSignature = h.hexdigest()
print(newData)
print(newSignature)

'''
print("BODY POST: \n"
          "     Original Data: {}\n"
          "     Original Signature: {}\n"
          "SECRET LENGTH: {}\n"
          "TYPE: md5\n"
          "APPEND: {}\n"
          "     Desired New Data: {}\n"
          "PADDING: {}\n"
          "     New Data: {}\n"
          "     New Signature: {}\n"
          .format(data, signature, secret_len, append, data+append, pad, newData, newSignature))

print(a(newData))

#SHA TEST COMPLETE

import sha1Ex, sha256Ex, sha512Ex, hashlib

data = "file"
secret_len = 6
append = "hello"
signature = "acfe143d9dc2edfe3af6a4fee89250cc6896233a"
print(signature)
h = sha1Ex.sha1Ex(data,signature,secret_len,append)
print(h.extend())
print("SHA1 -> " + h.hexdigest())
print(h.getHex())
print

secret = "secret"
data = "Hello"
append = "World"
secret_len = 6
signature = hashlib.sha256(b"secretHello").hexdigest()
print(signature)
h = sha256Ex.sha256Ex(data,signature,secret_len,append)
print(h.extend())
print("SHA256 -> " + h.hexdigest())
print(h.getHex())
print

secret = "secret"
data = "Hello"
append = "World"
secret_len = 6
signature = hashlib.sha512(b"secretHello").hexdigest()
print(signature)
h = sha512Ex.sha512Ex(data,signature,secret_len,append)
print(h.extend())
print("SHA512 -> " + h.hexdigest())
print(h.getHex())
print
'''



