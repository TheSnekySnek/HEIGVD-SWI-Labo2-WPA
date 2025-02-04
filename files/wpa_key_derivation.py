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
ssid        = "SWI"
APmac       = ""
Clientmac   = ""

# Authenticator and Supplicant Nonces
ANonce      = ""
SNonce      = ""

# This is the MIC contained in the 4th frame of the 4-way handshake
# When attacking WPA, we would compare it to our own MIC calculated using passphrases from a dictionary
mic_to_test = ""

data        = ""

# Empty values to compare to
emptyNONCE = b"0000000000000000000000000000000000000000000000000000000000000000"
emptyMIC = b"00000000000000000000000000000000"

# Iterate over each packet
for pkt in wpa:
    # Check if we have a 802.11 packet and haven't found the WiFi mac yet
    if pkt.haslayer(Dot11) and APmac == "":
        try:
            # Check if the packet contains the right ssid 
            if pkt.info.decode('ascii') == ssid:
                #Register the mac of the ap
                APmac = pkt[Dot11].addr2.replace(":", "")
                print("Found SSID MAC", APmac)
        except Exception:
            pass
    
    # Check foe EAPOL packet
    if pkt.haslayer(EAPOL):
        src = pkt[Dot11].addr2.replace(":", "")
        dst = pkt[Dot11].addr1.replace(":", "")
        to_DS = pkt[Dot11].FCfield & 0x1 !=0
        from_DS = pkt[Dot11].FCfield & 0x2 !=0

        # If the packet id from DS
        if from_DS == True and src == APmac:
            nonce = hexlify(pkt[Raw].load)[26:90]
            mic = hexlify(pkt[Raw].load)[154:186]

            # If we have a nonce and an empty mac we have the first message
            if nonce != emptyNONCE and mic == emptyMIC:
                APmac = src; Clientmac = dst
                print("M1")
                ANonce = nonce
            
            # Else if the client and ap are the right ones and we have a mic and a nonce it's the message 3
            elif src == APmac and dst == Clientmac and nonce != emptyNONCE and mic != emptyMIC:
                print("M3")
        # Else if it's to DS
        elif to_DS == True and dst == APmac:
            nonce = hexlify(pkt[Raw].load)[26:90]
            mic = hexlify(pkt[Raw].load)[154:186]
            # If the client and ap are the right and we have a nonce and a mic we have the second message
            if src == Clientmac and dst == APmac and nonce != emptyNONCE and mic != emptyMIC:
                print("M2")
                SNonce = nonce

            # Else if the client and ap are the right and we have no nonce and a mic we have the 4th message
            elif src == Clientmac and dst == APmac and nonce == emptyNONCE and mic != emptyMIC:
                print("M4")
                mic_to_test = a2b_hex(mic)

                # retrieve data
                data = raw(pkt[EAPOL]).replace(mic_to_test, b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
                print(data)


    ### This part is a fix for parsing packets in Windows ###
    # This is the same process as the code above

    # Check for association request
    elif pkt.haslayer(Dot11AssoReq):
        # the mac is broken here for some reason so we have to get it manualy
        dst = ''.join('%02x' % b for b in raw(pkt)[18:24]) 
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
print ("Passphrase:\t",passPhrase)
print ("SSID:\t\t",ssid)
print ("AP Mac:\t\t",APmac.encode())
print ("Cient Mac:\t",Clientmac.encode())
print ("AP Nonce:\t",ANonce)
print ("Client Nonce:\t",SNonce)

B = min(a2b_hex(APmac),a2b_hex(Clientmac))+max(a2b_hex(APmac),a2b_hex(Clientmac))+min(a2b_hex(ANonce),a2b_hex(SNonce))+max(a2b_hex(ANonce),a2b_hex(SNonce))

#calculate 4096 rounds to obtain the 256 bit (32 oct) PMK
passPhrase = str.encode(passPhrase)
ssid = str.encode(ssid)
pmk = pbkdf2(hashlib.sha1,passPhrase, ssid, 4096, 32)

#expand pmk to obtain PTK
ptk = customPRF512(pmk,str.encode(A),B)

#calculate MIC over EAPOL payload (Michael)- The ptk is, in fact, KCK|KEK|TK|MICK
mic = hmac.new(ptk[0:16],data,hashlib.sha1)


print ("\nResults of the key expansion")
print ("=============================")
print ("PMK:\t\t",pmk.hex())
print ("PTK:\t\t",ptk.hex())
print ("KCK:\t\t",ptk[0:16].hex())
print ("KEK:\t\t",ptk[16:32].hex())
print ("TK:\t\t",ptk[32:48].hex())
print ("MICK:\t\t",ptk[48:64].hex())
print ("MIC:\t\t",mic.hexdigest())