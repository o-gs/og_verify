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
import os
import re
import binascii
import argparse
from Crypto.Hash import MD5
from ctypes import *

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

def patch_cfg(cfg_file, module_file):
    cfg = open(cfg_file, "r")

    module_data = open(module_file, "rb").read()
    digest = MD5.new()
    digest.update(module_data)

    len_header = sizeof(ImageHeader)
    len_chunk = sizeof(ImageChunk)

    header = ImageHeader.from_buffer_copy(bytearray(module_data[0:len_header]))
    chunk  = ImageChunk.from_buffer_copy(bytearray(module_data[len_header:len_header + len_chunk]))

    name = chunk.id.decode()
    try:
        type_num = re.search('_..\d{2}\.pro' , module_file).group(0).split('.')[0][1:]
    except:
        type_num=""

    version = str(header.version[3]).zfill(2) + '.' + \
              str(header.version[2]).zfill(2) + '.' + \
              str(header.version[1]).zfill(2) + '.' + \
              str(header.version[0]).zfill(2)

    for line in cfg:
        if line.find(' id="%s" ' % name) != -1 and line.find(' type="%s" ' % type_num) != -1:
            line = re.sub(' md5="[^"]*"', ' md5="%s"' % binascii.hexlify(digest.digest()).decode(), line)
            line = re.sub('>[^<]*</module>', '>%s</module>' % os.path.basename(module_file), line)
            line = re.sub(' size="[^"]*"', ' size="%d"' % len(module_data), line)
            line = re.sub(' version="[^"]*"', ' version="%s"' % version, line)
            print(line, end='')
        else:
            print(line, end='')

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-c', '--cfg', required=True, help='.cfg file to patch.')
    parser.add_argument('-s', '--sig', required=True, help='.sig file to update in the cfg file.')
    args = parser.parse_args()

    patch_cfg(args.cfg, args.sig)

# vim: expandtab:ts=4:sw=4
