#!/usr/bin/env python3

# Copyright (C) 2018  Jan Dumon <jan@crossbar.net>
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys
import argparse
import os
import hashlib
import binascii
import datetime
import re
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from ctypes import *

SLEK = bytes([ 0x56, 0x79, 0x6C, 0x0E, 0xEE, 0x0F, 0x38, 0x05, 0x20, 0xE0, 0xBE, 0x70, 0xF2, 0x77, 0xD9, 0x0B ])

SLAK = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7AF5tZo4gtcUG
n//Vmk8XnDn2LadzEjZhTbs9h0X674aBqsri+EXPU+oBvpNvoyeisfX0Sckcg2xI
D6CUQJeUD4PijT9tyhis2PRU40xEK7snEecAK25PMo12eHtFYZN8eZVeySmnlNyU
bytlUrXEfRXXKzYq+cHVlOS2IQo2OXptWB4Ovd05C4fgi4DFblIBVjE/HzW6WJCP
IDf53bnzxXW0ZTH2QGdnQVe0uYT5Bvjp8IU3HRSy1pLZ35u9f+kVLnLpRRhlHOmt
xipIl1kxSGGkBkJJB76HdtcoOJC/O95Fl/qxSKzHjlg7Ku/gcUxmMZfvBi6Qih78
krJW0A+zAgMBAAECggEBALYZbtqj8qWBvGJuLkiIYprARGUpIhXZV2E7u6j38Lqi
w13Dvpx1Xi2+LnMSbSpaO/+fwr3nmFMO28P0i8+ycqj4ztov5+N22L6A6rU7Popn
93DdaxBsOpgex0jlnEz87w1YrI9H3ytUt9RHyX96ooy7rigA6VfCLPJacrm0xOf1
OIoJeMnGTeMSQlAFR+JzU5qdHHTcWi1WFNekzBgmxIXp6zZUkep/9+mxD7V8kGT2
MsJ/6IICe4euHA9lCpctYOPEs48yZBDljQfKD5FxVMUWBbXOhoCff99HeuW/4uVj
AO2mFp293nnGIV0Ya5PyDtGd+w/n8kcehFcfbfTvzZkCgYEA4woDn+WBXCdAfxzP
yUnMXEHB6189R9FTzoDwv7q3K48gH7ptJo9gq0+eycrMjlIGRiIkgyuukXD4FHvk
kkYoQ51Xgvo6eTpADu1CffwvyTi/WBuaYqIBH/HMUvFOLZu/jmSEsusXMTDmZxb+
Wpox17h1qMtNlyIqOBLyHcmTsy8CgYEA0trrk6kwmZC2IjMLswX9uSc5t3CYuN6V
g8OsES/68jmJxPYZTj0UidXms5P+V1LauFZelBcLaQjUSSmh1S95qYwM5ooi5bjJ
HnVH/aaIJlKH2MBqMAkBx6EtXqzo/yqyyfEZvt8naM8OnqrKrvxUCfdVx0yf7M7v
wECxxcgOGr0CgYBo198En781BwtJp8xsb5/nmpYqUzjBSXEiE3kZkOe1Pcrf2/87
p0pE0efJ19TOhCJRkMK7sBhVIY3uJ6hNxAgj8SzQVy1ZfgTG39msxCBtE7+IuHZ6
xcUvM0Hfq38moJ286747wURcevBq+rtKq5oIvC3ZXMjf2e8VJeqYxtVmEQKBgAhf
75lmz+pZiBJlqqJKq6AuAanajAZTuOaJ4AyytinmxSUQjULBRE6RM1+QkjqPrOZD
b/A71hUu55ecUrQv9YoZaO3DMM2lAD/4coqNkbzL7F9cjRspUGvIaA/pmDuCS6Wf
sOEW5e7QwojkybYXiZL3wu1uiq+SLI2bRDRR1NWVAoGANAp7zUGZXc1TppEAXhdx
jlzAas7J21vSgjyyY0lM3wHLwXlQLjzl3PgIAcHEyFGH1Vo0w9d1dPRSz81VSlBJ
vzP8A7eBQVSGj/N5GXvARxUswtD0vQrJ3Ys0bDSVoiG4uLoEFihIN0y5Ln+6LZJQ
RwjPBAdCSsU/99luMlK77z0=
-----END PRIVATE KEY-----"""

class ImageHeader(LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('magic_num', c_char * 4),          #0
                ('header_version', c_uint),         #4
                ('size', c_uint),                   #8
                ('reserved', c_char * 4),           #12
                ('header_size', c_uint),            #16
                ('signature_size', c_uint),         #20
                ('payload_size', c_uint),           #24
                ('target_size', c_uint),            #28
                ('os', c_ubyte),                    #32
                ('arch', c_ubyte),                  #33
                ('compression', c_ubyte),           #34
                ('anti_version', c_ubyte),          #35
                ('auth_alg', c_uint),               #36
                ('auth_key', c_char * 4),           #40
                ('enc_key', c_char * 4),            #44
                ('scram_key', c_ubyte * 16),        #48
                ('name', c_char * 32),              #64
                ('type', c_uint),                   #96
                ('version', c_ubyte * 4),           #100
                ('date', c_uint),                   #104
                ('reserved2', c_uint * 5),          #108
                ('userdata', c_uint * 4),           #128
                ('entry', c_ulonglong),             #144
                ('reserved3', c_uint),              #152
                ('chunk_num', c_uint),              #156
                ('payload_digest', c_ubyte * 32)]   #160 end is 192

class ImageChunk(LittleEndianStructure):
    _pack_ = 1
    _fields_ = [('id', c_char * 4),                 #0
                ('offset', c_uint),                 #4
                ('size', c_uint),                   #8
                ('attrib', c_uint),                 #12
                ('addr', c_ulonglong),              #16
                ('reserved', c_ulonglong)]          #24 end is 32

def sign(filename, name, chunk_id, version, encrypt, separate_header):

    ver = re.search('^v(\d+).(\d+).(\d+).(\d+)$', version)
    if ver == None:
        print('ERROR: Wrong version string format (vAA.BB.CC.DD): ' + version)
        return -1

    if not chunk_id:
        chunk_id = name

    if encrypt and separate_header:
        print('ERROR: Creating a separate signature AND encrypt the file is currently not supported')
        return -1

    image_file = open(filename, "rb")
    image_data = image_file.read()
    image_file.close()

    pad_cnt = (AES.block_size - len(image_data) % AES.block_size) % AES.block_size
    padded_length = len(image_data) + pad_cnt
    pad32_cnt = padded_length % 32
    padded_length += pad32_cnt

    header = ImageHeader()
    header.magic_num = bytes("IM*H", "utf-8")
    header.header_version = 1
    header.size = 224 + 256 + padded_length
    header.header_size = 224
    header.signature_size = 256
    header.payload_size = padded_length
    header.target_size = 224 + 256 + padded_length
    header.auth_alg = 1
    header.auth_key = bytes("SLAK", "utf-8")
    header.enc_key = bytes("SLEK", "utf-8")
    header.name = bytes(name, "utf-8")
    header.version[3] = int(ver.group(1))
    header.version[2] = int(ver.group(2))
    header.version[1] = int(ver.group(3))
    header.version[0] = int(ver.group(4))
    n = datetime.datetime.now()
    header.date = ((n.year // 1000) << 28) | (((n.year % 1000) // 100) << 24) | (((n.year % 100) // 10) << 20) | ((n.year % 10) << 16) |\
                  ((n.month // 10) << 12) | ((n.month % 10) << 8) | ((n.day // 10) << 4) | (n.day % 10)
    header.chunk_num = 1

    scram_key = os.urandom(16)
    cipher = AES.new(SLEK, AES.MODE_ECB)
    header.scram_key = (c_ubyte * 16)(*list(cipher.encrypt(scram_key)))
    cipher = AES.new(scram_key, AES.MODE_CBC, bytes([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))

    chunk = ImageChunk()
    chunk.id = bytes(chunk_id, "utf-8")
    chunk.size = len(image_data)

    output_file = open(filename + ".sig", "wb")

    if encrypt:
        pad_byte = bytes(chr(pad_cnt), "utf-8")
    else:
        pad_byte = bytes(chr(0), "utf-8")

    for _ in range(pad_cnt):
        image_data += pad_byte

    if encrypt:
        encrypted_data = cipher.encrypt(image_data)
    else:
        chunk.attrib = 1
        encrypted_data = image_data

    for _ in range(pad32_cnt):
        encrypted_data += bytes(chr(0), "utf-8")
        
    digest = SHA256.new()
    digest.update(encrypted_data)
    header.payload_digest = (c_ubyte * 32)(*list(digest.digest()))

    key = RSA.importKey(SLAK)
    signer = PKCS1_v1_5.new(key)
    digest = SHA256.new()
    digest.update(header)
    digest.update(chunk)

    output_file.write(header)
    output_file.write(chunk)
    output_file.write(signer.sign(digest))

    if not separate_header:
        output_file.write(encrypted_data)

    output_file.close()

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', '--file', required=True, help='File to sign.')
    parser.add_argument('-n', '--name', required=True, help='Name of the signed file.')
    parser.add_argument('-c', '--chunk', help='Name of the chunk. If omitted, <name> will be used.')
    parser.add_argument('-v', '--version', required=True, help='Version string in the form "vAA.BB.CC.DD"')
    parser.add_argument('-e', '--encrypt', default=False, action='store_true', help='Encrypt the file')
    parser.add_argument('-H', '--header', default=False, action='store_true', help='Only create the signature header')
    args = parser.parse_args()

    sign(args.file, args.name, args.chunk, args.version, args.encrypt, args.header)

# vim: expandtab:ts=4:sw=4
