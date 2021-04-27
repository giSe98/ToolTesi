from pwn import *
from subprocess import getoutput

if args.REMOTE:
	p = remote('challenges.tamuctf.com', 8812)
else:
	p = process(['python', 'game.py'])

menu = '1. New Game\n2. Claim Prize\n3. Exit\n'
welcome = '''
            Welcome the The Game. You are allowed to multiply the initial number (which is 1) by any
            number in the range 2-10. Make decisions wisely! You can only multiply by each
            number at most 5 times... so be careful. Also, at a random point during The Game, an asteroid
            will impact the Earth and The Game will be over.

            Feel free to get your proof of achievement and claim your prize at the main menu once
            you start reaching big numbers. Bet you can't beat my high score!\n'''
game_menu = '1. Multiply\n2. Print current value\n3. Get proof and quit\n'
p.recvuntil(menu)

# Get the hash value of 1
p.sendline(str(1))
p.recvuntil(welcome)
p.recvuntil(game_menu)
p.sendline(str(3))
originalSignature = p.recvline(keepends=False).decode()

# Creating a default payload
append = '1' * 50
args = ' -s "{}" '.format(originalSignature)
args += '-d 1 '
args += '-a "{}" '.format(append)
args += '-f sha512 '
args += '-l {}'

# Bruteforce the keylength
for keylength in range(1, 128):
    argsTool = args.format(keylength)
    output = getoutput('python hashBreaker.py' + argsTool)
    newData = output.split("\n")[2].split(":")[1].strip().encode().decode('unicode-escape')
    newSignature = output.split("\n")[3].split(":")[1].strip() 
    
    # Try newData and newSignature
    p.sendline(str(2))
    p.recvuntil('Input the number you reached: \n')
    p.sendline(newData)
    p.recvuntil('Present the proof of your achievement: \n')
    p.sendline(newSignature)
    response = p.recvline(keepends=False).decode()
    if 'gigem{' in response:
    	print("newData -> " + newData)
    	print("HASH -> " + newSignature)
    	print("KEY LENGTH -> " + str(keylength))
    	log.success('flag = {}'.format(response))
    	quit()

p.interactive()
