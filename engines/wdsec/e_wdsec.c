/**
 * Implet a cipher engine use the wd framework API
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/opensslconf.h>
#include <openssl/crypto.h>
#include <openssl/dso.h>
#include <openssl/engine.h>
#include <openssl/evp.h>
#include <openssl/aes.h>
#include <error.h>
#include <sys/mman.h>
#include <sys/ioctl.h>

#include "wd.h"
#include "wd_cipher.h"

#ifdef WDSEC_OPENSSL_DBG
	#define WDSEC_DBG printf
#else
	#define WDSEC_DBG
#endif

static const char *wd_engine_id = "wdsec";
static const char *wd_engine_name = "A cipher engine using wrapdrive API";
static const ENGINE_CMD_DEFN wd_engine_cmd_defns[] = {
	{0, NULL, NULL, 0}
};

/* Tell openssl the engine's capability, this is necessary s*/
static int engine_cipher_nids[] = {
	NID_des_ede3_cbc, NID_aes_128_cbc,
	NID_aes_192_cbc, NID_aes_256_cbc,
};

static int engine_cipher_nids_num = 4;

#define ASIZE (2024*1024)

struct wd_engine_cipher_ctx {
	struct wd_cipher_msg msg;
	struct wd_queue *q;
	void *vaddr;
};

static void wd_engine_cipher_ctx_construct(EVP_CIPHER_CTX *ctx,
	struct wd_queue *q)
{
	struct wd_engine_cipher_ctx *cipher_ctx;
	struct wd_capa capa;

	cipher_ctx = (struct wd_engine_cipher_ctx *)ctx->cipher_data;
	memset(cipher_ctx, 0 ,sizeof(*cipher_ctx));

	cipher_ctx->q = q;
	capa = q->capa;
	cipher_ctx->msg.alg = capa.alg;
	cipher_ctx->msg.status = 0;
	//cipher_ctx->msg.dsize = EVP_CIPHER_CTX_block_size(ctx);//todo zhaoshaopeng
	cipher_ctx->msg.keylen = EVP_CIPHER_CTX_key_length(ctx);
	cipher_ctx->msg.optype = ctx->encrypt ? WD_CIPHER_ENCRYPT : WD_CIPHER_DECRYPT;

	printf("construction complete\n");

}

static char g_key[32] = {0};
static int wd_engine_ase_128_cbc_init(EVP_CIPHER_CTX *ctx,
	const unsigned char *key, const unsigned char *iv, int enc)
{
	struct wd_engine_cipher_ctx *cipher_ctx;
	struct wd_capa capa;
	struct wd_aalg_calg_param *calg;
	struct wd_queue *q;
	int ret;

	q = malloc(sizeof(*q));
	if (!q)
		return 0;
	memset(&capa, 0, sizeof(capa));
	calg = (struct wd_aalg_calg_param *)capa.priv;
	capa.alg = cbc_aes_128;
	/* todo: EVP_CIPHER_CTX_key_length or EVP_CIPHER_key_length */
	calg->cparam.key_size = EVP_CIPHER_CTX_key_length(ctx);
	calg->cparam.iv_size = EVP_CIPHER_CTX_iv_length(ctx);
	ret = wd_request_queue(q, &capa);
	if (ret) {
		printf("wd_request_queue fail! \n");
		return -1;
	}

	wd_engine_cipher_ctx_construct(ctx, q);
	cipher_ctx = ctx->cipher_data;

	//
	#if 0
		size = EVP_CIPHER_CTX_block_size(ctx);
		dst = (void *)cipher_ctx->dma_map.vaddr + size;
		memset(dst, 0, size);
		pkey = dst + size;
		memcpy(pkey, key, cipher_ctx->msg.keylen);
		piv = pkey + cipher_ctx->msg.keylen;
		memcpy(piv, iv, EVP_CIPHER_CTX_iv_length(ctx));

		cipher_ctx->msg.iv = (__u64)piv;
		cipher_ctx->msg.key = (__u64)pkey;
	#else
		memcpy(g_key, key, cipher_ctx->msg.keylen);
	#endif
	return 1;
}

static int wd_enging_aes_128_cbc_cipher(EVP_CIPHER_CTX *ctx,
	unsigned char *out, const unsigned char *in, size_t in_len)
{
	struct wd_engine_cipher_ctx *cipher_ctx = (struct wd_engine_cipher_ctx *)ctx->cipher_data;
	unsigned char *src, *dst, *key, *iv;
	struct wd_cipher_msg *resp;
	int ret;
	const void *iiv;
	unsigned char save_iv[EVP_MAX_IV_LENGTH];


	printf("%s, in_len=%ld\n", __func__, in_len);
	if (in_len > 8192){
		printf("unsupported in_len for now\n");
		return -1;
	}

	if (!in_len)
		return 1;
	if ((in_len % ctx->cipher->block_size) != 0)
		return 0;
	/* Allocate some space and setup a DMA mapping */
	cipher_ctx->vaddr = mmap(NULL, ASIZE,
	  PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	/* todo
	 * handle mmap return
	 */
	//dosth...
	if (!cipher_ctx->vaddr) {
		printf("mmap fail\n");
		return -1;
	}

	ret = wd_mem_share(cipher_ctx->q, cipher_ctx->vaddr, ASIZE, 0);
	if (ret) {
		printf("wd_mem_share fail\n");
		return -1;
	}
	src = cipher_ctx->vaddr;
	memcpy(src, in, in_len);
	dst = cipher_ctx->vaddr + in_len;
	memset(dst, 0, in_len);
	key = (void *)dst + in_len;
	memcpy(key, g_key, cipher_ctx->msg.keylen);
	iv = key + cipher_ctx->msg.keylen;

	if (EVP_CIPHER_CTX_iv_length(ctx)) {
		memcpy(iv, ctx->iv, EVP_CIPHER_CTX_iv_length(ctx));
		cipher_ctx->msg.iv = (__u64)iv;
		if (!ctx->encrypt) {
			iiv = in + in_len - EVP_CIPHER_CTX_iv_length(ctx);
			memcpy(save_iv, iiv, EVP_CIPHER_CTX_iv_length(ctx));
		}
	}

	cipher_ctx->msg.src = (__u64)src;
	cipher_ctx->msg.dst = (__u64)dst;
	cipher_ctx->msg.key = (__u64)key;
	cipher_ctx->msg.dsize = (__u32)in_len;
	ret = wd_send(cipher_ctx->q, &cipher_ctx->msg);
	if (ret) {
		printf("wd_send_fail!!!\n");
		return -1;
	}
	ret = wd_recv_sync(cipher_ctx->q, (void **)&resp, 0);
	if (ret < 0) {
		printf ("wd recv fail!\n");
		return -1;
	} else if (ret == 0) {
		printf ("wd recv nothing!\n");
		return -1;
	} else if (ret == 1){
			printf("wd_recv_success \n");
			memcpy(out, (void *)cipher_ctx->msg.dst, in_len);//todo
			if (EVP_CIPHER_CTX_iv_length(ctx)) {
				if (ctx->encrypt)
					iiv = out + in_len - EVP_CIPHER_CTX_iv_length(ctx);
				else
					iiv = save_iv;
				//update ctx->iv
				memcpy(ctx->iv, iiv, EVP_CIPHER_CTX_iv_length(ctx));
			}
			return 1;
	} else
		return -1;
}

static int wd_engine_cipher_cleanup(EVP_CIPHER_CTX *ctx)
{
	struct wd_engine_cipher_ctx *cipher_ctx = (struct wd_engine_cipher_ctx *)ctx->cipher_data;

	printf("%s\n", __func__);
	munmap((void *)cipher_ctx->vaddr, ASIZE);
	wd_release_queue(cipher_ctx->q);
	free(cipher_ctx->q);

	return 1;
}

static const EVP_CIPHER wd_engine_aes_128_cbc =
{
	NID_aes_128_cbc,
	16,
	16,
	16,
	EVP_CIPH_CBC_MODE,
	wd_engine_ase_128_cbc_init,
	wd_enging_aes_128_cbc_cipher,
	wd_engine_cipher_cleanup,
	sizeof(struct wd_engine_cipher_ctx),
	EVP_CIPHER_set_asn1_iv,
	EVP_CIPHER_get_asn1_iv,
	NULL,
	NULL
};

static int wd_engine_ciphers(ENGINE *e, const EVP_CIPHER **cipher,
	const int **nids, int nid)
{
	if (!cipher) {
		*nids = engine_cipher_nids;
		return engine_cipher_nids_num;
	}
	switch (nid) {
	case NID_aes_128_cbc:
		*cipher = &wd_engine_aes_128_cbc;
		return 1;
	default:
		*cipher = NULL;
		return 0;

	}
}


static int wd_engine_destroy(ENGINE *e)
{
	//ERR_unload_hatk_strings();//todo
	printf("%s\n", __func__);
	return 1;
}


static int wd_engine_init(ENGINE *e)
{
	//resource init //todo
	printf("%s\n", __func__);
	return 1;
}

static int wd_engine_finish(ENGINE *e)
{
	//resource release
	printf("%s\n", __func__);
	return 1;
}

static int wd_engine_ctrl(ENGINE *e, int cmd, long i, void *p, void (*f)(void))
{
	//do nothing for now//todo
	return 1;
}



static int bind_wd(ENGINE *e, const char *id)
{
	if (id && (strcmp(id, wd_engine_id)))
		return 0;

	if (!ENGINE_set_id(e, wd_engine_id) ||
		!ENGINE_set_name(e, wd_engine_name) ||
		!ENGINE_set_ciphers(e, wd_engine_ciphers) ||
		!ENGINE_set_destroy_function(e, wd_engine_destroy) ||
		!ENGINE_set_init_function(e, wd_engine_init) ||
		!ENGINE_set_finish_function(e, wd_engine_finish) ||
		!ENGINE_set_ctrl_function(e, wd_engine_ctrl) ||
		!ENGINE_set_cmd_defns(e, wd_engine_cmd_defns))
		return 0;

	/* error handling */
	//ERR_load_wd_strings();//todo
	return 1;
}


IMPLEMENT_DYNAMIC_CHECK_FN()
IMPLEMENT_DYNAMIC_BIND_FN(bind_wd)
