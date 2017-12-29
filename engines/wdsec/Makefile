
CC := aarch64-linux-gnu-gcc
AR := aarch64-linux-gnu-ar

INCLUDES += -I../../include/ -I./include/

# PUB_HEADER=wd.h wd_cipher.h wd_dummy.h wd_util.h wd_cipher_usr_if.h wd_dummy_usr_if.h wd_usr_if.h
OBJ = wdsec.o ./lib/libwd.o ./lib/libcrypto.o

wdsec.so : $(OBJ) 
	$(CC) -shared -o $@ $^

wdsec.o : e_wdsec.c
	$(CC) $(INCLUDES) -fPIC -Wall $(CFLAGS) -o $@ -c $<
		
clean:
	rm wdsec.o wdsec.so
