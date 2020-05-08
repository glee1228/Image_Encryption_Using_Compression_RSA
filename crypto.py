#!/usr/bin/python
import zlib
import base64
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import Crypto.Hash.SHA
from PIL import Image
import io
import codecs

def keygen():
    key = RSA.generate(1024, e=65537)
    public = key.publickey().exportKey("PEM")
    private = key.exportKey("PEM")
    return public, private

def encrypt(plaintext, key, VERBOSE=True):
    ## Returns base64 encrypted plaintext

    chunk_size = 128 - 2 - 2 * Crypto.Hash.SHA.digest_size
    if VERBOSE: print('\tCompressing: %d bytes' % len(plaintext))
    plaintext = zlib.compress(plaintext)

    if VERBOSE: print("\tEncrypting %d bytes" % len(plaintext))
    rsakey = RSA.importKey(key)
    rsakey = PKCS1_OAEP.new(rsakey)

    encrypted = b""
    offset = 0

    while offset < len(plaintext):
        chunk = plaintext[offset:offset + chunk_size]
        if len(chunk) % chunk_size != 0:
            added_chunk = chunk_size - len(chunk)
            chunk += b" " * added_chunk

        encrypted += rsakey.encrypt(chunk)
        offset += chunk_size

    if added_chunk < 0x10:
        encrypted = ("0x0" + str(hex(added_chunk))[2:]).encode() + encrypted

    else:
        encrypted = hex(added_chunk).encode() + encrypted

    if VERBOSE: print("\tEncrypted: %d bytes" % len(encrypted))

    encrypted = base64.b64encode(encrypted)
    return encrypted


def decrypt(plaintext, key, VERBOSE=True):
    rsakey = RSA.importKey(key)
    rsakey = PKCS1_OAEP.new(rsakey)

    chunk_size = 128
    offset = 0
    decrypted = b""
    encrypted = base64.b64decode(plaintext)

    added_chunk = int(encrypted[:4], base=0)
    encrypted = encrypted[4:]
    if VERBOSE: print("\tDecrypt: %d bytes " % len(encrypted))

    while offset < len(encrypted):
        decrypted += rsakey.decrypt(encrypted[offset:offset + chunk_size])
        offset += chunk_size

    decrypted = decrypted[:(len(decrypted) - added_chunk)]

    if VERBOSE: print("\tDecompress: %d bytes " % len(decrypted))
    decrypted = zlib.decompress(decrypted)
    if VERBOSE: print("\tDecompressed: %d bytes " % len(decrypted))
    return decrypted


if __name__ == '__main__':
    # filename = "./bmp_data/cat3.bmp"
    filename = "./jpg_data/cat.jpg"
    fd = codecs.open(filename, "rb")
    img = fd.read()
    fd.close()

    public, private = keygen()

    encrypted_message = encrypt(img, public)
    decrypted_message = decrypt(encrypted_message,private)

    print('decrypted img length : {} '.format(len(decrypted_message)))
    img2 = Image.open(io.BytesIO(decrypted_message))
    img2.save('./byte_to_img/decrypted.png')

