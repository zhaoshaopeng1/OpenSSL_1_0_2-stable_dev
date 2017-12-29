/*
 * Copyright (c) 2017 Hisilicon Limited.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */


/* This file is shared bewteen WD user and kernel space, which is
* including attibutions of user caring for
*/

#ifndef __WD_CIPHER_IF_H
#define __WD_CIPHER_IF_H


/* General symmetric cipher core algorithms */
enum wd_cipher_alg {
	WD_CA_NO_CIPHER,
	WD_CA_AES,
	WD_CA_DES,
	WD_CA_3DES,
	WD_CA_ZUC,
	WD_CA_KASUMI,
	WD_CA_SNOW3G,
	WD_CA_TWOFISH,
	WD_CA_BLOWFISH,
	WD_CA_RC4,
	WD_CA_RC2,
	WD_CA_CAMELLIA,
	WD_CA_IDEA,
	WD_CA_CAST5,
};

/* General symmetric block cipher mode */
enum wd_cipher_mode {
	WD_CM_NO_MODE,
	WD_CM_CBC,
	WD_CM_ECB,
	WD_CM_CTR,
	WD_CM_GCM,
	WD_CM_CCM,
	WD_CM_XTS,
	WD_CM_OFB,
	WD_CM_CFB,
	WD_CM_WRAP,
};

/* Auth/digest algorithms are defined as the following */
enum wd_auth_alg {
	WD_AA_MD2,
	WD_AA_MD4,
	WD_AA_MD5,
	WD_AA_SHA1,
	WD_AA_SHA160,
	WD_AA_SHA224,
	WD_AA_SHA256,
	WD_AA_SHA384,
	WD_AA_SHA512,
	WD_AA_HMAC_SHA160_96,
	WD_AA_HMAC_SHA160,
	WD_AA_HMAC_SHA224_96,
	WD_AA_HMAC_SHA224,
	WD_AA_HMAC_SHA256_96,
	WD_AA_HMAC_SHA256,
	WD_AA_HMAC_MD5_96,
	WD_AA_HMAC_MD5,
	WD_AA_AES_XCBC_MAC_96,
	WD_AA_AES_XCBC_PRF_128,
	WD_AA_AES_CMAC,
};

/* Cipher algorithms' parameters */
struct wd_calg_param {
	__u8 key_size;
	__u8 iv_size;
	__u8 pad[2];
};

/* Auth algorithms' parameters */
struct wd_aalg_param {
	__u8 key_size;
	__u8 mac_size;
	struct  {
		__u8 min_size;
		__u8 max_ssize;
		__u8 inc_ssize;
	} aad_ssize;
	__u8 pad[3];
};

/* Cipher-auth chaining algorithms' parameters */ 
struct wd_aalg_calg_param {
	struct wd_calg_param cparam;
	struct wd_aalg_param aparam;
};


/* WD defines all the algorithm names here */
#define cbc_aes_128		"cbc_aes_128"
#define cbc_aes_192		"cbc_aes_192"
#define cbc_aes_256		"cbc_aes_256"
#define ctr_aes_128		"ctr_aes_128"
#define ctr_aes_192		"ctr_aes_192"
#define ctr_aes_256		"ctr_aes_256"
#define ecb_aes_128		"ecb_aes_128"
#define ecb_aes_192		"ecb_aes_192"
#define ecb_aes_256		"ecb_aes_256"

#define md5			"md5"
#define sha160			"sha160"
#define sha224			"sha224"
#define sha256			"sha256"


#endif
