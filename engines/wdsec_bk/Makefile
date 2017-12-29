
CC := aarch64-linux-gnu-gcc
AR := aarch64-linux-gnu-ar

PUB_HEADER=wd.h wd_cipher.h wd_cipher_if.h wd_dummy_cpy_if.h wd_usr_if.h wd_util.h vfio.h
OBJ = wdsec.o libwd.o libcrypto.o

INCLUDES += -I../../include/

wdsec.so : $(OBJ) 
	$(CC) -shared -o $@ $^

wdsec.o : e_wdsec.c $(PUB_HEADER)
	$(CC) $(INCLUDES) -fPIC -Wall $(CFLAGS) -o $@ -c $<
		
clean:
	rm wdsec.o wdsec.so
#  e_wdsec.c libwd.a libcrypto.a $(PUB_HEADER)