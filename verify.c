/*  Copyright (C) 2018  Jan Dumon <jan@crossbar.net>
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <stdint.h>
#include <getopt.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/mman.h>

#include "mincrypt/rsa.h"
#include "mincrypt/sha256.h"
#include "aes.h"

#define min(a, b) ((a) < (b) ? (a) : (b))

enum dji_image_chunk_attr {
    DJI_IMAGE_CHUNK_CLEAR = 0x1,
};

struct dji_image_chunk {
    uint32_t id;
    uint32_t offset;
    uint32_t size;
    uint32_t attr;
    uint64_t addr;
    uint64_t reserved;
};

typedef struct dji_image_chunk dji_image_chunk_t;

struct dji_image_header {
    uint32_t magic_num;
    uint32_t header_version;
    uint32_t size;
    uint32_t reserved;
    uint32_t header_size;
    uint32_t signature_size;
    uint32_t payload_size;
    uint32_t target_size;
    uint8_t os;
    uint8_t arch;
    uint8_t compression;
    uint8_t anti_version;
    uint32_t auth_alg;
    uint32_t auth_key;
    uint32_t enc_key;
    uint8_t scram_key[16];
    uint8_t name[32];
    uint32_t type;
    uint32_t version;
    uint32_t date;
    uint32_t reserved2[5];
    uint32_t userdata[4];
    uint64_t entry;
    uint32_t reserved3;
    uint32_t chunk_num;
    uint8_t payload_digest[32];
    dji_image_chunk_t chunk[];
};

typedef struct dji_image_header dji_image_header_t;

#define SWAP(i) (((i) >> 24) | (((i) & 0x00ff0000 )>> 8) | (((i) & 0x0000ff00) << 8) | ((i) << 24))
#define STR2ID(n) SWAP((uint32_t)n)

/* GogglesRE */
//static uint8_t PUEK[16] = { 0x77, 0x0d, 0xe4, 0xe3, 0xcc, 0x0c, 0x95, 0x7b, 0x03, 0x00, 0x6f, 0xfe, 0x02, 0xa3, 0xd4, 0x66 };

/* Mavic */
static uint8_t PUEK[16] = { 0x63, 0xc4, 0x8e, 0x83, 0x26, 0x7e, 0xee, 0xc0, 0x3f, 0x33, 0x30, 0xad, 0xb2, 0x38, 0xdd, 0x6b };

static uint8_t SLEK[16] = { 0x56, 0x79, 0x6C, 0x0E, 0xEE, 0x0F, 0x38, 0x05, 0x20, 0xE0, 0xBE, 0x70, 0xF2, 0x77, 0xD9, 0x0B };

static RSAPublicKey PRAK = {
    .len = 64,
    .n0inv = 0x411615c3l,
    .n = {
        0x44307d15, 0x5889ee8f, 0x2e3384d6, 0x3c21288b, 0x23c905db, 0x2dfe6ae0, 0x481b3713, 0x2f87c287,
        0x4974d67f, 0x1700250e, 0xcf9f3a18, 0xdd9f10b4, 0x5f556ad8, 0x8db074c8, 0xb7c41964, 0xb8037efa,
        0x8fa006f1, 0x268c1e57, 0x23fc32a5, 0x7f0ddde1, 0x5296d4e4, 0x50bc083b, 0x6b8a23d9, 0x377db5aa,
        0xfd3a3fa1, 0x8b4c2891, 0x5eb4e298, 0xcbbd87cb, 0x76d891e6, 0x2977904f, 0x0d6c230b, 0xebb2f48d,
        0x66f3a23b, 0xee7a9671, 0x63c24efb, 0x50d7e4c9, 0x607fd906, 0x4888eba5, 0x7d70424b, 0xa1b9280a,
        0xcf6a5216, 0x7e8ec98b, 0x9aa0aa97, 0xb6c8e2a5, 0x2c7aabaa, 0x733c2821, 0xd7ec68d6, 0xebb824f0,
        0xa578f2ba, 0x64a0b687, 0x03075d52, 0x8d2eb6c5, 0x5956b6f7, 0xff87cb13, 0x78e56eb9, 0x9c32a5d8,
        0xc11c8393, 0xa4047185, 0x5b9dbaf2, 0x03a55500, 0x466fc405, 0x1a64d49a, 0x948fa91f, 0x94fdbd92 },
    .rr = {
        0xfccb94e0, 0x4bb05ad9, 0x0040f3d7, 0x20edde10, 0x1d36cdcf, 0xda5f2fdb, 0x28a7ad87, 0xd79cfb5a,
        0xda531952, 0x88b273db, 0xec00fbed, 0x789e76dd, 0x9442cad2, 0xc1906564, 0xb854598d, 0xfd0bd046,
        0xf9302e68, 0x1f0de170, 0x24e760e9, 0x47053a02, 0xd98ca64e, 0x2f588d73, 0x561839cb, 0xa65bc83a,
        0xff647941, 0x0a71f1fa, 0x875d2f3d, 0x7624500b, 0xabc21248, 0xf84cf26f, 0x20d2e60e, 0x37a316c7,
        0xc9d9bca4, 0x5e7be104, 0xf66e229f, 0x06354a99, 0x7a8cee35, 0x20d8136f, 0x1e7cb8f9, 0x6e20baf8,
        0x7ee15678, 0xd67e9a1d, 0x7c3cb2b7, 0x969d0014, 0xde75a722, 0x1ddc5f57, 0xdf579ed1, 0x815cc690,
        0x5fb00ca8, 0x808031a7, 0x9bff1da6, 0x6722850d, 0xfdc6e8d6, 0x87271e53, 0x29ffb7ba, 0xf2388a81,
        0x16b4c2e6, 0x3b1cf198, 0xc64a0c2a, 0x426a966a, 0x7cce3bce, 0xcc1e5f8d, 0x55ff4395, 0x3bdf09f3 },
    .exponent = 65537
};

static RSAPublicKey GFAK = {
    .len = 64,
    .n0inv = 0x88a8579b,
    .n = {
        0x043ec96d, 0x8e80141e, 0x3710d838, 0x4869976d, 0x4a4b78e8, 0x814846c0, 0x99abc3fc, 0x397512c6,
        0xeb63c91e, 0x6a3d8ed5, 0xfc60c44e, 0x27dbe11a, 0x70f89c0d, 0x639e87fc, 0xe699713b, 0x2e87f4a2,
        0xf21dfcfa, 0x02b37473, 0x213f3519, 0x752e97d8, 0x0a04b5fe, 0x2f48b250, 0xdf916525, 0x56aac663,
        0xb20633a6, 0x8f11ce96, 0x152e3ab4, 0x455aa392, 0x13490479, 0xc6a17fa4, 0x05fa3f84, 0x7d1bb47f,
        0x5da9e409, 0x39bc8a21, 0x96e26cc6, 0xa8e82586, 0xf9fe6542, 0xaab8ba51, 0x9f85b223, 0x4226fcdf,
        0xc98dce6a, 0x634cdd3f, 0x7468f584, 0xc83bdd40, 0xd69e18c7, 0xb5a963d4, 0x704d8f46, 0x76fd4dd5,
        0xc8ad80e6, 0x94c384ff, 0x1f7d6e41, 0xf978233a, 0x8ac4ef93, 0xcd5a9929, 0x06305817, 0xc370a274,
        0x1dccea0c, 0x523f8af6, 0xe81267ca, 0x44cfbaea, 0xb91905f1, 0x903120e3, 0xa9e8e8c4, 0xc9f187bf },
    .rr = {
        0xf0382849, 0x662ca4e7, 0x4d147351, 0xf175d403, 0x939447d9, 0x80dab27b, 0xd0ceb697, 0xaa70d3f9,
        0x2ca98a57, 0xcd197a29, 0xe954085a, 0xd3a9f57c, 0x8145665f, 0x1807169a, 0x0207c2f6, 0x40425dd3,
        0x240d9bae, 0x73590684, 0xb4dd0e89, 0x19beb4a8, 0xccd7cda8, 0x07715552, 0xc12f5da6, 0x7ac8e3bf,
        0xad685d16, 0x3901592f, 0xfbc04101, 0xb2f7aef1, 0x75dd9ea8, 0x649b5707, 0x4eb98783, 0x5cf1e2ba,
        0x5e1efe96, 0x85ccf8cf, 0xf6a673ce, 0x0b26d77c, 0x079838c7, 0xbaedbaec, 0x8a169305, 0x48bbee03,
        0xb5c2fc05, 0xe3162bb7, 0x62978efd, 0x0be17bfc, 0x8dd98574, 0x13a88609, 0xa8fe77d7, 0x7e6d2408,
        0x87592a1a, 0xc2dddd17, 0x683d0151, 0x8e305e78, 0x1362d436, 0x6aa0d39f, 0x3b49c7d0, 0x82951a1a,
        0x5596d7de, 0x5539fd88, 0x1391ea56, 0x477c14a8, 0x5ae4afed, 0xdab7a830, 0x9eed0dce, 0x80933247 },
    .exponent = 65537
};

static RSAPublicKey SLAK = {
    .len = 64,
    .n0inv = 0x4dccc885,
    .n = {
        0x56d00fb3, 0x1efc92b2, 0x062e908a, 0x663197ef, 0xefe0714c, 0x8e583b2a, 0xb148acc7, 0xde4597fa,
        0x3890bf3b, 0x8776d728, 0x424907be, 0x4861a406, 0x48975931, 0xe9adc62a, 0x4518651c, 0x152e72e9,
        0x9bbd7fe9, 0xd692d9df, 0x371d14b2, 0xf8e9f085, 0xb984f906, 0x674157b4, 0x31f64067, 0xc575b465,
        0xf9ddb9f3, 0x908f2037, 0x1f35ba58, 0x0156313f, 0x80c56e52, 0x0b87e08b, 0x0ebddd39, 0x7a6d581e,
        0x210a3639, 0xd594e4b6, 0x362af9c1, 0x7d15d72b, 0x6552b5c4, 0xdc946f2b, 0xc929a794, 0x7c79955e,
        0x7b456193, 0x328d7678, 0x002b6e4f, 0xbb2711e7, 0xe34c442b, 0xacd8f454, 0x3f6dca18, 0x0f83e28d,
        0x94409794, 0x6c480fa0, 0x49c91c83, 0xa2b1f5f4, 0x936fa327, 0x53ea01be, 0xe2f845cf, 0x8681aaca,
        0x8745faef, 0x614dbb3d, 0xa7731236, 0x9c39f62d, 0xd59a4f17, 0xc5069fff, 0x668e20b5, 0xbb005e6d },
    .rr = {
        0x9cbb3077, 0xd852ac69, 0x5981f6c4, 0x635a16c3, 0x23445267, 0x8e818a79, 0x8968319b, 0x04926e22,
        0x2d4697e1, 0x0c86bf58, 0x80bf97f9, 0x255c8866, 0xa1b4ea26, 0x700ede02, 0x2ded0917, 0x0a3bd64b,
        0xefcc595c, 0x8321d8f3, 0x64687297, 0x9144198e, 0x0eda692a, 0x69861c64, 0x50176a76, 0x4c428793,
        0x7de983b0, 0x83b970cc, 0x14e8930c, 0x35809f46, 0xb1da3724, 0x164ca941, 0xe07af8f0, 0xaf680f31,
        0x72f89566, 0xa8c32e99, 0x2400bca0, 0xdeac27f7, 0x186d0286, 0xa3081315, 0x1384eff0, 0x6c5d922a,
        0xfac35cab, 0xe96eef63, 0xbe291e71, 0x2a29645a, 0x524d30eb, 0x64b0f34c, 0x94aa772f, 0x975aed87,
        0x7cff46a7, 0x78b1711b, 0x8b828e68, 0x24a45e86, 0x89f64464, 0x53db98c7, 0xc411f61a, 0x3243ea50,
        0xd3e0932c, 0xca218e23, 0x7fec8a84, 0x3aa9a221, 0x826d608c, 0xeef4f611, 0xb95e7c18, 0x07d4dd42 },
    .exponent = 65537
};

static struct enc_key_entry {
    uint32_t key_id;
    uint8_t  *key;
} enc_keys[] = {
    { STR2ID('PUEK'), PUEK },
    { STR2ID('SLEK'), SLEK },
    { 0, NULL },
};

static struct auth_key_entry {
    uint32_t key_id;
    RSAPublicKey *key;
} auth_keys[] = {
    { STR2ID('PRAK'), &PRAK },
    { STR2ID('GFAK'), &GFAK },
    { STR2ID('SLAK'), &SLAK },
    { 0, NULL },
};

static char *id2str(uint32_t key) {
    static char buffer[5];
    *(uint32_t *)buffer = key;
    return buffer;
}

static void help(const char *name, int exitvalue) {
    printf("verify image\n"
           "       %s [option] -o <out_file> <in_file>\n"
           "option:\n"
           "  -h, --help              show this help messagen\n"
           "  -n, --name              image name\n"
           "  -c, --chunk             chunk id in string\n"
           "  -H, --header=FILE       input seperated header file name,\n"
           "                          in such case, in_file is payload only\n"
           "  -o, --output=FILE       output file name,\n"
           "                          output to stdout by default\n"
           "\n"
           "[Slack OG edition]\n",
           name);
    exit(exitvalue);
}

static const struct option longopts[] =
{
  { "help",   no_argument,       NULL, 'h' },
  { "name",   required_argument, NULL, 'n' },
  { "chunk",  required_argument, NULL, 'c' },
  { "header", required_argument, NULL, 'H' },
  { "output", required_argument, NULL, 'o' },
  { NULL,     0,                 NULL, 0 }
};

static void hexdump(uint8_t *p, int len) {
    while (len--)
        printf("%02x ", *p++);
    printf("\n");
}

static void hexdump32(uint32_t *p, int len) {
    while (len--)
        printf("%08x ", *p++);
    printf("\n");
}

static void *map_file(char *filename) {
    int fd = open(filename, O_RDONLY);
    struct stat statbuf;
    char *buffer = NULL;

    if (fd >= 0) {
        fstat(fd, &statbuf);
        buffer = mmap(NULL, statbuf.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
        close(fd);
    }

    return buffer;
}

int main(int argc, const char **argv) {
    int opt;
    int ret = 0;
    int verbose = 0;
    char *input = NULL;
    char *output = NULL;
    char *header = NULL;
    char *image_name = NULL;
    char *chunk_name = NULL;

    while ((opt = getopt_long(argc, (char * const *)argv, "o:H:n:c:hv", longopts, 0)) != -1) {
        switch (opt) {
            case 'o':
                output = optarg;
                break;
            case 'H':
                header = optarg;
                break;
            case 'n':
                image_name = optarg;
                break;
            case 'c':
                chunk_name = optarg;
                break;
            case 'h':
                help(argv[0], 0);
                break;
            case 'v':
                verbose = 1;
                break;
            default:
                printf("unknown option : -%c\n", opt);
                help(argv[0], -1);
        }
    }

    if (optind == argc) {
        printf("must input source image\n");
        help(argv[0], -1);
    }
    else {
        input = (char *)argv[optind];
    }

    if (!image_name) {
        printf("must input image name\n");
        help(argv[0], -1);
    }

    unsigned char *hdr_buffer = NULL;
    unsigned char *payload = NULL;
    dji_image_header_t *hdr = NULL;

    if (header) {
        hdr_buffer = map_file(header);
        hdr = (dji_image_header_t *)hdr_buffer;
        payload = map_file(input);
    }
    else {
        hdr_buffer = map_file(input);
        hdr = (dji_image_header_t *)hdr_buffer;
        payload = hdr_buffer + hdr->header_size + hdr->signature_size;
    }

    if (hdr->magic_num != STR2ID('IM*H')) {
        printf("Invalid header magic!\n");
        exit(1);
    }

    if (verbose) {
        printf("magic:          %s\n", id2str(hdr->magic_num));
        printf("header_version: %d\n", hdr->header_version);
        printf("size:           %d\n", hdr->size);
        printf("reserved:       %08x\n", hdr->reserved);
        printf("header_size:    %d / %lu\n", hdr->header_size, sizeof(*hdr));
        printf("signature_size: %d\n", hdr->signature_size);
        printf("payload_size:   %d\n", hdr->payload_size);
        printf("target_size:    %d\n", hdr->target_size);
        printf("os:             %d\n", hdr->os);
        printf("arch:           %d\n", hdr->arch);
        printf("compression:    %d\n", hdr->compression);
        printf("anti_version:   %d\n", hdr->anti_version);
        printf("auth_alg:       %d\n", hdr->auth_alg);
        printf("auth_key:       %s\n", id2str(hdr->auth_key));
        printf("enc_key:        %s\n", id2str(hdr->enc_key));
        printf("scram_key:      ");
        hexdump(hdr->scram_key, 16);
        printf("name:           %s\n", hdr->name);
        printf("type:           %d\n", hdr->type);
        printf("version:        %08x\n", hdr->version);
        printf("date:           %08x\n", hdr->date);
        printf("reserved2:      ");
        hexdump32(hdr->reserved2, 5);
        printf("userdata:       ");
        hexdump32(hdr->userdata, 4);
        printf("entry:          %016llx\n", hdr->entry);
        printf("reserved3:      %08x\n", hdr->reserved3);
        printf("chunk_num:      %d\n", hdr->chunk_num);
        printf("payload_digest: ");
        hexdump(hdr->payload_digest, 32);
    }

    if (strcmp((const char *)hdr->name, image_name) != 0) {
        printf("Invalid image name!\n");
        exit(1);
    }

    if (chunk_name && (strcmp(id2str(hdr->chunk[0].id), chunk_name) != 0)) {
        printf("Invalid chunk name!\n");
        exit(1);
    }

    if (verbose) {
        printf("chunk id:       %s\n", id2str(hdr->chunk[0].id));
        printf("chunk offset:   %d\n", hdr->chunk[0].offset);
        printf("chunk size:     %d\n", hdr->chunk[0].size);
        printf("chunk attr:     %08x\n", hdr->chunk[0].attr);
    }

    RSAPublicKey *auth_key;
    struct auth_key_entry *auth_iter = auth_keys;
    while ((auth_key = auth_iter->key) && auth_iter->key_id != 0 && auth_iter->key_id != hdr->auth_key)
        auth_iter++;

    if (!auth_key) {
        printf("Unsupported auth key: %s\n", id2str(hdr->auth_key));
        exit(1);
    }

    uint8_t *enc_key;
    struct enc_key_entry *enc_iter = enc_keys;
    while ((enc_key = enc_iter->key) && enc_iter->key_id != 0 && enc_iter->key_id != hdr->enc_key)
        enc_iter++;

    if (!enc_key) {
        printf("Unsupported encryption key: %s\n", id2str(hdr->enc_key));
        exit(1);
    }

    unsigned char hash[32];

    SHA256_hash(hdr, hdr->header_size, hash);
    ret = RSA_verify(auth_key,
               (const unsigned char*)hdr + hdr->header_size,
               hdr->signature_size,
               hash,
               sizeof(hash));

    if (ret != 1) {
        printf("Header signature verification failed\n");
        exit(1);
    }

    SHA256_hash(payload, hdr->payload_size, hash);
    if (memcmp(hash, hdr->payload_digest, 32) != 0) {
        printf("Digest verification failed\n");
        exit(1);
    }

    if (output) {
        int fd2 = open(output, O_CREAT | O_TRUNC | O_WRONLY, 0644);
        if (hdr->chunk[0].attr & DJI_IMAGE_CHUNK_CLEAR) {
            write(fd2, payload, hdr->chunk[0].size);
        }
        else {
            uint8_t scram_key[16];
            unsigned char iv[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            AesCtx ctx;

            if( AesCtxIni(&ctx, NULL, enc_key, KEY128, EBC) < 0) {
                printf("Failed to init AES\n");
                exit(1);
            }

            if (AesDecrypt(&ctx, hdr->scram_key, scram_key, sizeof(scram_key)) < 0) {
                printf("Failed to decrypt\n");
                exit(1);
            }

            if( AesCtxIni(&ctx, iv, scram_key, KEY128, CBC) < 0) {
                printf("Failed to init AES\n");
                exit(1);
            }

            unsigned char *outbuf = malloc(1024);
            if (!outbuf) {
                printf("Failed to allocate 1024 bytes\n");
                exit(1);
            }

            int padded_len = (((hdr->chunk[0].size + 15) / 16) * 16);
            int pos = 0;
            while (padded_len) {
                int n = min(padded_len, 1024);
                if (AesDecrypt(&ctx, payload + pos, outbuf, n) < 0) {
                    printf("Failed to decrypt\n");
                    exit(1);
                }
                pos += n;
                padded_len -= n;

                if (pos > hdr->chunk[0].size)
                n = hdr->chunk[0].size - (pos - n);
                write(fd2, outbuf, n);
            }
        }
        close(fd2);
    }

    printf("Slack OG Done !\n");

    exit(0);

    return ret;
}

/* vim: expandtab:ts=4:sw=4
*/
