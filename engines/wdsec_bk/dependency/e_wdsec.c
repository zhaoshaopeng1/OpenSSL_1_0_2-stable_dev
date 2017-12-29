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

struct wd_engine_cipher_ctx {
	struct wd_cipher_msg msg;
	struct wd_queue *q;
	struct vfio_iommu_type1_dma_map dma_map;
	struct vfio_iommu_type1_dma_unmap dma_unmap;
};

static void wd_engine_cipher_ctx_construct(EVP_CIPHER_CTX *ctx,
	struct wd_queue *q)
{
	struct wd_engine_cipher_ctx *cipher_ctx;
	struct wd_capa capa;
	int ret;
	printf("%s\n", __func__);
	cipher_ctx = (struct wd_engine_cipher_ctx *)ctx->cipher_data;
	memset(cipher_ctx, 0 ,sizeof(*cipher_ctx));

	cipher_ctx->q = q;
	capa = q->capa;
	cipher_ctx->msg.alg = capa.alg;
	cipher_ctx->msg.status = 0;
	cipher_ctx->msg.dsize = EVP_CIPHER_CTX_block_size(ctx);
	cipher_ctx->msg.keylen = EVP_CIPHER_CTX_key_length(ctx);
	cipher_ctx->msg.optype = ctx->encrypt ? WD_CIPHER_ENCRYPT : WD_CIPHER_DECRYPT;
	printf("zhaoshaopeng optype=%d encrypt=%d\n", cipher_ctx->msg.optype, ctx->encrypt);
	cipher_ctx->msg.aflags |= WD_CAPA_MEMS_FLAT;

	/* for dma_map */
	cipher_ctx->dma_map.vaddr = (__u64)mmap(0, 1024 * 1024,
		PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
	cipher_ctx->dma_map.size = 1024 * 1024;
	cipher_ctx->dma_map.iova = cipher_ctx->dma_map.vaddr;
	cipher_ctx->dma_map.flags = VFIO_DMA_MAP_FLAG_READ | VFIO_DMA_MAP_FLAG_WRITE;
	cipher_ctx->dma_map.argsz = sizeof(cipher_ctx->dma_map);

	ret = ioctl(q->container, VFIO_IOMMU_MAP_DMA, &cipher_ctx->dma_map);
	if (ret)
		//todo handle error
		printf("dma map fail");

	/* for dma_unmap */
	cipher_ctx->dma_unmap.iova = cipher_ctx->dma_map.iova;
	cipher_ctx->dma_unmap.argsz = sizeof(cipher_ctx->dma_unmap);
	cipher_ctx->dma_unmap.flags = 0;
	cipher_ctx->dma_unmap.size = cipher_ctx->dma_map.size;
	printf("construction complete\n");
}

static int wd_engine_ase_128_cbc_init(EVP_CIPHER_CTX *ctx,
	const unsigned char *key, const unsigned char *iv, int enc)
{
	printf("%s\n", __func__);
	struct wd_engine_cipher_ctx *cipher_ctx;
	struct wd_capa capa;
	struct wd_aalg_calg_param *calg;
	struct wd_queue *q;
	unsigned char *dst, *pkey, *piv;
	int ret, size;

	q = malloc(sizeof(*q));
	if (!q)
		return 0;
	memset(&capa, 0, sizeof(capa));
	calg = (struct wd_aalg_calg_param *)capa.priv;
	capa.alg = cbc_aes_128;
	/* todo: EVP_CIPHER_CTX_key_length or EVP_CIPHER_key_length */
	calg->cparam.key_size = EVP_CIPHER_CTX_key_length(ctx);
	calg->cparam.iv_size = EVP_CIPHER_CTX_iv_length(ctx);
	capa.flags |= WD_CAPA_MEMS_FLAT;
	ret = wd_request_queue(q, &capa);
	if (ret) {
		printf("wd_request_queue fail! \n");
		return 0;
	}

	wd_engine_cipher_ctx_construct(ctx, q);
	cipher_ctx = ctx->cipher_data;

	//
	size = EVP_CIPHER_CTX_block_size(ctx);
	dst = (void *)cipher_ctx->dma_map.vaddr + size;
	memset(dst, 0, size);
	pkey = dst + size;
	memcpy(pkey, key, cipher_ctx->msg.keylen);
	piv = pkey + cipher_ctx->msg.keylen;
	memcpy(piv, iv, EVP_CIPHER_CTX_iv_length(ctx));

	cipher_ctx->msg.iv = (__u64)piv;
	cipher_ctx->msg.key = (__u64)pkey;

	return 1;
}

static int wd_enging_aes_128_cbc_cipher(EVP_CIPHER_CTX *ctx,
	unsigned char *out, const unsigned char *in, size_t in_len)
{
	struct wd_engine_cipher_ctx *cipher_ctx = (struct wd_engine_cipher_ctx *)ctx->cipher_data;
	unsigned char *src, *dst;
	struct wd_cipher_msg *resp;
	int ret, size;

	printf("%s\n", __func__);
	size = EVP_CIPHER_CTX_block_size(ctx);
	src = (void *)cipher_ctx->dma_map.vaddr;
	dst = (void *)cipher_ctx->dma_map.vaddr + size;
	memcpy(src, in, size);
	cipher_ctx->msg.src = (__u64)src;
	cipher_ctx->msg.dst = (__u64)dst;
	printf("wd_enging_aes_128_cbc_cipher 1111111 src=%s, in_len=%ld, key=%s\n", in, in_len, (void *)cipher_ctx->msg.key);
	ret = wd_send(cipher_ctx->q, &cipher_ctx->msg);
	if (ret) {
		printf("wd_send_fail");
		return 0;
	}
	usleep(100);

	ret = wd_recv(cipher_ctx->q, (void **)&resp);
	//shaopeng todo maybe ret=1 means successful?
	if (ret) {
		//printf("wd_recv_fail ret = %d \n", ret);
		//return 0;
	}

	printf("wd_enging_aes_128_cbc_cipher 3333333 (void *)resp->dst=%s\n", (void *)resp->dst);
	printf("zhaoshaopeng wd_enging_aes_128_cbc_cipher 444444 cipher_ctx->msg.dst=%s \n", (void *)cipher_ctx->msg.dst);
	//memcpy(out, (void *)resp->dst, size);
	printf("wd_enging_aes_128_cbc_cipher 55555\n");

	return 1;

}

static int wd_engine_cipher_cleanup(EVP_CIPHER_CTX *ctx)
{
	struct wd_engine_cipher_ctx *cipher_ctx = (struct wd_engine_cipher_ctx *)ctx->cipher_data;
	int ret;

	printf("%s\n", __func__);
	ret = ioctl(cipher_ctx->q->container, VFIO_IOMMU_UNMAP_DMA, cipher_ctx->dma_unmap);
	if (ret){
		printf("dma unmap surccessfully");
	}
	munmap((void *)cipher_ctx->dma_map.vaddr, 1024 * 1024);
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
	printf("%s\n", __func__);

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
