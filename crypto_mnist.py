#!/usr/bin/python
import zlib
import base64
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
import Crypto.Hash.SHA
from PIL import Image
import io
import codecs
import ctypes
import numpy as np
import binascii
import os
import multiprocessing
from tqdm import tqdm

def keygen():
    key = RSA.generate(1024, e=65537)
    public = key.publickey().exportKey("PEM")
    private = key.exportKey("PEM")
    return public, private

def utf16_decimals(char, chunk_size=2):
    # encode the character as big-endian utf-16
    encoded_char = char.encode('utf-16-be')

    # convert every `chunk_size` bytes to an integer
    decimals = []
    for i in range(0, len(encoded_char), chunk_size):
        chunk = encoded_char[i:i+chunk_size]
        decimals.append(int.from_bytes(chunk, 'big'))

    return decimals

def encrypt(plaintext, key, VERBOSE=True, COMPRESS=False):
    ## Returns base64 encrypted plaintext
    chunk_size = 67 - 2 - 2 * Crypto.Hash.SHA.digest_size

    if COMPRESS:
        if VERBOSE: print('\tCompressing: %d bytes' % len(plaintext))
        plaintext = zlib.compress(plaintext)

    if VERBOSE: print("\tEncrypting %d bytes" % len(plaintext))
    rsakey = RSA.importKey(key)
    rsakey = PKCS1_OAEP.new(rsakey)

    encrypted = b""
    offset = 0
    added_chunk=0
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


    # encrypted = base64.b64encode(encrypted)
    return encrypted


def decrypt(encrypted, key, VERBOSE=True,DECOMPRESS=False):
    rsakey = RSA.importKey(key)
    rsakey = PKCS1_OAEP.new(rsakey)

    chunk_size = 128
    offset = 0
    decrypted = b""
    # encrypted = base64.b64decode(encrypted)

    added_chunk = int(encrypted[:4], base=0)
    encrypted = encrypted[4:]
    if VERBOSE: print("\tDecrypt: %d bytes " % len(encrypted))

    while offset < len(encrypted):
        decrypted += rsakey.decrypt(encrypted[offset:offset + chunk_size])
        offset += chunk_size

    decrypted = decrypted[:(len(decrypted) - added_chunk)]


    if DECOMPRESS :
        if VERBOSE: print("\tDeCompress: %d bytes " % len(decrypted))
        decrypted = zlib.decompress(decrypted)

    if VERBOSE: print("\tDecrypted: %d bytes " % len(decrypted))

    return decrypted

# binary data를 gray scale matrix로 반환하는 함수
def getMatrix(content,width):
    hexst = binascii.hexlify(content)
    fh = np.array([int(hexst[i:i+2],16) for i in range(0, len(hexst), 2)])
    rn = len(fh)/width
    rn = int(rn)
    fh = np.reshape(fh[:rn*width],(-1,width))
    fh = np.uint8(fh)
    return fh

def getImagefrom_bytes(pointer, size, width, height, rotation, VERBOSE=True):
    raw_bytes = ctypes.string_at(pointer, size=size)

    if VERBOSE: print("\tImaging: %d bytes " % len(raw_bytes))

    if rotation == 0:
        image = Image.frombytes("RGBA", (width, height), raw_bytes)
    elif rotation == 90:
        image = Image.frombytes("RGBA", (height, width), raw_bytes)
        image = image.transpose(Image.ROTATE_270)
    elif rotation == 180:
        image = Image.frombytes("RGBA", (width, height), raw_bytes)
        image = image.transpose(Image.ROTATE_180)
    elif rotation == 270:
        image = ctypes.string_at(pointer, size=size)
        image = image.transpose(Image.ROTATE_90)

    b, g, r, _ = image.split()
    image = Image.merge("RGB", (r, g, b))

    return image

def makedir(path):
    if os.path.exists(os.path.join(path)) == False:
        os.mkdir(path)
def is_image(filename):
    return any(filename.endswith(ext) for ext in EXTENSIONS)

def image_path(root, basename, extension):
    return os.path.join(root, f'{basename}{extension}')

def image_basename(filename):
    return os.path.basename(os.path.splitext(filename)[0])

def encrypt_process(bytes,iteration,result_root='./mnist_encrypted',VERBOSE=True):
    public, private = keygen()
    enc = encrypt(bytes, public, VERBOSE)
    enc = getMatrix(enc, 64)
    enc = Image.fromarray(enc)
    w,h = enc.size
    out_path = image_path(result_root, filename + '_%04d_%d_%d' % (iteration, w, h), '.png')
    enc.save(out_path)
    if iteration %1000==0:
        print('result shape : ', enc.size)


EXTENSIONS = ['.jpg', '.png','.bmp']

if __name__ == '__main__':
    images_root = './mnist'
    result_root = './mnist_encrypted'
    makedir(result_root)

    number_data_create = 5000
    number_process_batches = 100
    epochs = int(number_data_create/number_process_batches)
    filenames = [image_basename(f) for f in os.listdir(images_root) if is_image(f)]
    print(filenames)

    for filename in filenames:
        print('start filename :', filename)
        path=image_path(images_root, filename, '.bmp')
        fd = codecs.open(path, "rb")
        img = fd.read()
        fd.close()
        image = Image.open(io.BytesIO(img))
        # pixel 정보만 갖고 암호화 -> matrix 변환하기
        img_bytes = image.tobytes()
        manager = multiprocessing.Manager()
        jobs = []
        for epoch in tqdm(range(0,epochs ), desc='epoch..'):
            for i in tqdm(range(0, number_process_batches), desc="batching..(Multi-processing)"):
                # it = (epoch * number_process_batches) + i
                p = multiprocessing.Process(target=encrypt_process, args=(img_bytes, (epoch * number_process_batches) + i,result_root,False))
                jobs.append(p)
                p.start()

            for proc in jobs:
                proc.join()
            jobs = []

