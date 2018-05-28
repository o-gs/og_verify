
ARCH ?= x86

NDK_BUNDLE ?= $(HOME)/Library/Android/sdk/ndk-bundle
HOST ?= darwin-x86_64

ifeq ($(ARCH), arm)
  CROSS_COMPILE = $(NDK_BUNDLE)/toolchains/arm-linux-androideabi-4.9/prebuilt/$(HOST)/bin/arm-linux-androideabi-
  CFLAGS =  -I$(NDK_BUNDLE)/sysroot/usr/include/arm-linux-androideabi
  CFLAGS += -I$(NDK_BUNDLE)/sysroot/usr/include
  CFLAGS += -Wno-multichar -Wno-attributes
  LDFLAGS += --sysroot=$(NDK_BUNDLE)/platforms/android-16/arch-arm
  LDFLAGS += -s
endif

CC = $(CROSS_COMPILE)gcc
CFLAGS += -Isrc -O3

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

og_verify: src/verify.o src/rsa.o src/sha.o src/sha256.o src/aes.o
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

clean:
	rm -f og_verify src/*.o

