#
# OpenSSL/engines/test/Makefile
#

OUTPUT_NAME1=EngineTester

INCLUDES += -I../../include/ \
#			-I/home/zhaoshaopeng/bin/gcc-linaro-5.3.1-2016.05-x86_64_aarch64-linux-gnu/bin/

LIBS := -lrt -ldl -lpthread -lstdc++ -lc #-L../../ -lcrypto -Wl,-rpath,../../

USER_SOURCE_FILES += EngineTester.c

USER_INCLUDES= $(INCLUDES)
SAMPLE_CIPHER_CFLAGS += $(USER_INCLUDES)
SAMPLE_CIPHER_CFLAGS += $(LIBS)
# -flax-vector-conversions -DLINUX_USER -D_GNU_SOURCE -ldl #-march=armv8-a -mtune=cortex-a57 -mcpu=cortex-a57 -flax-vector-conversions -DLINUX_USER -D_GNU_SOURCE

#CC = aarch64-linux-gnu-gcc
#CC=gcc

$(OUTPUT_NAME1):EngineTester.c ../../libcrypto.a
	-$(RM) EngineTester
	$(CC) -o $@ $^  $(SAMPLE_CIPHER_CFLAGS) 
	
clean:
	rm EngineTester

