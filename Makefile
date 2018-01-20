
ARCH ?= x86

NDK_BUNDLE ?= $(HOME)/Library/Android/sdk/ndk-bundle
HOST ?= darwin-x86_64

ifeq ($(ARCH), arm)
  LTC_TOP = ../libtomcrypt-arm
  CROSS_COMPILE = $(NDK_BUNDLE)/toolchains/arm-linux-androideabi-4.9/prebuilt/$(HOST)/bin/arm-linux-androideabi-
  CFLAGS =  -I$(NDK_BUNDLE)/sysroot/usr/include/arm-linux-androideabi
  CFLAGS += -I$(NDK_BUNDLE)/sysroot/usr/include
  CFLAGS += -Wno-multichar -Wno-attributes
  #LDFLAGS = -L/Volumes/bionic/android_build/out/target/product/generic/system/lib/
  LDFLAGS += --sysroot=$(NDK_BUNDLE)/platforms/android-16/arch-arm
  LDFLAGS += -s
else
  LTC_TOP = ../libtomcrypt
endif

CC = $(CROSS_COMPILE)gcc
LTC_INC = $(LTC_TOP)/src/headers
CFLAGS += -I. -I$(LTC_INC) -O3

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@ 

og_verify: verify.o rsa.o sha.o sha256.o
	$(CC) $(CFLAGS) -o $@ $^ $(LTC_TOP)/libtomcrypt.a $(LDFLAGS)

clean:
	rm -f og_verify *.o

