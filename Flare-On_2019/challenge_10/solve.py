"""
FL4rE-oN_5o_Ho7_R1gHt_NoW@flare-on.com
"""
import itertools
import string
import struct



def encrypt(n_rounds, data, key):
    v3 = data[0]
    v4 = data[1]
    v5 = 0
    for i in range(n_rounds):
        v6 = v5 + key[v5 & 3]
        v6 &= 0xFFFFFFFF

        v5 -= 0x61C88647
        v5 &= 0xFFFFFFFF

        v3 += v6 ^ (v4 + ((v4 >> 5) ^ 16 * v4)) #todo
        v3 &= 0xFFFFFFFF

        result = v5 + key[(v5 >> 11) & 3]
        result &= 0xFFFFFFFF

        v4 += result ^ (v3 + ((v3 >> 5) ^ 16 * v3))
        v4 &= 0xFFFFFFFF
    data[0] = v3 & 0xFFFFFFFF
    data[1] = v4 & 0xFFFFFFFF
    return result

def decrypt(n_rounds, data, key):
    v0 = data[0]
    v1 = data[1]
    delta = -0x61C88647
    for i in range(n_rounds)[::-1]:
        d1 = (delta*(i+1)) & 0xFFFFFFFF
        v1 -= (v0 + ((v0 >> 5) ^ (v0 << 4))) ^ (d1 + key[(d1 >> 11) & 3])
        v1 &= 0xFFFFFFFF

        d2 = (delta*(i)) & 0xFFFFFFFF
        v0 -= (v1 + ((v1 >> 5) ^ (v1 << 4))) ^ (d2 + key[d2 & 3])
        v0 &= 0xFFFFFFFF
        #print d1,(d1 >> 11) & 3,d2,d2 & 3
    data[0] = v0
    data[1] = v1


def test():
    data = "AAAABBBBCCCCDDDD"
    key = "MNOPQRSTMMMMMMMMMM"

    data = [0x41414141, 0x42424242]
    key = map(ord, "MNOP")

    encrypt(32, data, key)
    assert [0x674A7CA6, 0xAE3D88FA] == data


def encrypt_file(key, filename):
    out = ""
    offset = 0
    key = map(ord, key)

    with open(filename, "rb") as f:
        mugatu_file = f.read()

    while offset < len(mugatu_file):
        d0 = struct.unpack("I", mugatu_file[offset + 0: offset + 4])[0]
        d1 = struct.unpack("I", mugatu_file[offset + 4: offset + 8])[0]
        offset += 8

        data = [d0, d1]
        encrypt(32, data, key)
        p0 = data[0]
        p1 = data[1]
        out += struct.pack("I", p0)
        out += struct.pack("I", p1)
    return out

def decrypt_file(key, filename):
    out = ""
    offset = 0

    with open(filename, "rb") as f:
        mugatu_file = f.read()

    while offset < len(mugatu_file) and (len(mugatu_file) - offset) >= 8:
        d0 = struct.unpack("I", mugatu_file[offset + 0: offset + 4])[0]
        d1 = struct.unpack("I", mugatu_file[offset + 4: offset + 8])[0]
        offset += 8

        data = [d0, d1]
        decrypt(32, data, key)
        p0 = data[0]
        p1 = data[1]
        out += struct.pack("I", p0)
        out += struct.pack("I", p1)
    return out


def get_hint():
    key = [0,0,0,0]
    filename = "the_key_to_success_0000.gif.Mugatu"
    out = decrypt_file(key, filename)

    with open("the_key_to_success_0000.gif","wb") as f:
        f.write(out)

#get_hint()
key_hint = 0x31


def find_key():
    filename = "best.gif.Mugatu"
    with open(filename, "rb") as f:
        mugatu_file = f.read()

    for k in itertools.product(range(256), repeat=3):
        key = [key_hint] + list(k)
        d0 = struct.unpack("I", mugatu_file[0: 4])[0]
        d1 = struct.unpack("I", mugatu_file[4: 8])[0]
        data = [d0, d1]
        decrypt(32, data, key)
        if data[0] == 0x38464947:
            print "Found key:",map(hex, key)
            return key
    else:
        print "Key not found"
        return False

#print find_key()
key = [0x31, 0x73, 0x35, 0xb1]


filename = "best.gif.Mugatu"
flag = decrypt_file(key, "best.gif.Mugatu")
with open("best.gif", "wb") as f:
    f.write(flag)

"""

unpacks "fc030000"
    -sets env "fc030000"->"fc030000"

Gets computer info and xors that with the title of the latest tweek from derek
    - patch binary to have the correct url..
Uses `CryptBinaryToStringA()` to form it into a string

submits a POST to "mugatu.flare-on.com"
     - data of tweet sent as `Date` header
     - string send in body

receives response as a crypt string, calls `CryptStringToBinaryA()` to get it
    - CRYPT_STRING_BASE64

compares it with "orange mocha frappuccino\x00"
    - if it is, creates 2 events:  "F0aMy" and "L4tt3"
    - writes data after to "\\.\mailslot\Let_me_show_you_Derelicte"

loads dll
dll eventually waits on events from mutexes above..
once those resolve, it appears to encrypt files


encryption searches for a folder called "really, really, really, ridiculously good looking gifs"



```
v8 = 0;
if ( v11 / 8 > 0 )
{
    offset = base_address;
    do
    {
        sub_30416B9(32, offset, key_from_mailslot);
        offset += 8;
        ++v8;
    }
    while ( v8 < v11 / 8 );
    v5 = v13;
}
```

```
int __cdecl sub_30416B9(int i32, unsigned int *data, int key)
{
  unsigned int v3; // edi
  unsigned int v4; // ebx
  unsigned int v5; // esi
  int v6; // edx
  int result; // eax

  v3 = *data;
  v4 = data[1];
  v5 = 0;
  do
  {
    v6 = v5 + *(unsigned __int8 *)((v5 & 3) + key);
    v5 -= 0x61C88647;
    v3 += v6 ^ (v4 + ((v4 >> 5) ^ 16 * v4));
    result = v5 + *(unsigned __int8 *)(((v5 >> 11) & 3) + key);
    v4 += result ^ (v3 + ((v3 >> 5) ^ 16 * v3));
    --i32;
  }
  while ( i32 );
  *data = v3;
  data[1] = v4;
  return result;
}
```

looks to be this https://en.wikipedia.org/wiki/XTEA


"""

