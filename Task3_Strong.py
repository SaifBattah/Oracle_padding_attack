#!/usr/bin/python3
import socket
from binascii import hexlify, unhexlify


# XOR two bytearrays
def xor(first, second):
    return bytearray(x ^ y for x, y in zip(first, second))


class PaddingOracle:

    def __init__(self, host, port) -> None:
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.connect((host, port))

        ciphertext = self.s.recv(4096).decode().strip()
        self.ctext = unhexlify(ciphertext)

    def decrypt(self, ctext: bytes) -> None:
        self._send(hexlify(ctext))
        return self._recv()

    def _recv(self):
        resp = self.s.recv(4096).decode().strip()
        return resp

    def _send(self, hexstr: bytes):
        self.s.send(hexstr + b'\n')

    def __del__(self):
        self.s.close()


if __name__ == "__main__":
    oracle = PaddingOracle('10.9.0.80', 6000)

    # Get the IV + Ciphertext from the oracle
    iv_and_ctext = bytearray(oracle.ctext)
    print("Ciphertext: " + iv_and_ctext.hex())
    length = len(iv_and_ctext.hex())
    Number_Of_C_Blocks = (length / 32) - 1
    print("LEN = " + str(length))
    print("Number_Of_C_Blocks = " + str(Number_Of_C_Blocks))
    IV = iv_and_ctext[00:16]
    print("IV:    " + IV.hex())
    C = {}
    D = {}
    CC = {}
    P = {}
    Padded_text = ""
    for i in range (1,int(Number_Of_C_Blocks)+1):
    	C[i] = iv_and_ctext[16 * i: 16 * (i+1)]
    	print("C[" + str(i) + "]" + ":  " + C[i].hex())
    	
    for i in range(1, int(Number_Of_C_Blocks)+1):
    	D[i] = bytearray(16)
    	for k in range(0, 16):
    		if(i == 1):
    			D[i][k] = IV[k]
    		else:
    			D[i][k] = C[i - 1][k]
    
    for i in range(0, int(Number_Of_C_Blocks)):
    	CC[i] = bytearray(16)
    	for k in range(0,16):
    		CC[i][k] = 0x00

    ###############################################################

    ###############################################################
    # In each iteration, we focus on one byte of CC1.
    # We will try all 256 possible values, and send the constructed
    # ciphertext CC1 + C2 (plus the IV) to the oracle, and see
    # which value makes the padding valid.
    # As long as our construction is correct, there will be
    # one valid value. This value helps us get one byte of D2.
    # Repeating the method for 16 times, we get all the 16 bytes of D2.

    
    for m in range(0, int(Number_Of_C_Blocks)):
    	print("M = " + str(m))
    	for K in range(1, 17):
        	print(K)
        	# print("X: " + CC1.hex())
        	for i in range(256):
            		# print(" I LOOP -> " + CC1.hex())
            		CC[m][16 - K] = i
            		status = oracle.decrypt(IV + CC[m] + C[m+1])
            		if status == "Valid":
                			print("Valid: i = 0x{:02x}".format(i))
                			#print("CC2: " + CC2.hex())
                			D[m+1][16 - K] = CC[m][16 - K] ^ K
                			# print("RANGE = " + str(16 - K) + " to 16")
                			for j in range(16 - K, 16):
                    				# print("J = " + str(j))
                    				CC[m][j] = D[m+1][j] ^ (K + 1)
                			# print("| " + str(K) + " | "+  CC1.hex())
                			break

    
    for i in range (1, int(Number_Of_C_Blocks) + 1):
    	if i == 1:
    		P[i] = xor(IV, D[i])
    	else:
    		P[i] = xor(C[i - 1], D[i])
    		
    	print("P[" + str(i) + "]:  " + P[i].hex())
    	print("---------------------------------------------------------")
    	Padded_text += P[i].hex()
    
    print("Plain_Text [With padding] = " + Padded_text)