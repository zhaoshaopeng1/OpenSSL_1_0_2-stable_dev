



#include <openssl/engine.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <stdio.h>
#include <string.h>

int main(int argc, const char* argv[] ) {
    OpenSSL_add_all_algorithms();

    ERR_load_crypto_strings();

    ENGINE_load_dynamic();
    ENGINE *oezgan_engine = ENGINE_by_id("oezganengine");

    if( oezgan_engine == NULL )
    {
        printf("Could not Load Oezgan Engine!\n");
        exit(1);
    }
    printf("Oezgan Engine successfully loaded\n");

    int init_res = ENGINE_init(oezgan_engine);
    printf("Engine name: %s init result : %d \n",ENGINE_get_name(oezgan_engine), init_res);
    return 0;
}
