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

#ifndef __WD_USR_IF_H
#define __WD_USR_IF_H

#include <linux/types.h>

/* APIs of different Algorithm types */
#include "wd_cipher_if.h"
#include "wd_dummy_cpy_if.h"


/* Wrap drive version is v1.0 */
#define WD_VER 			10
#define WD_CLASS_NAME		"wrapdrive"
#define WD_DEV_ATTR		"wdev"
#define WD_MDEV_ATTR		"wd_mdev"
#define WD_CAPA_ATTR		"wd_capa"

/* Different algorithm kinds that WD engine supports, the classification
* is based on the function of algorithms.
*/
enum wd_alg_type {
	WD_AT_CUSTOMIZED,
	WD_AT_CY_SYM,		/* symmetric cipher */
	WD_AT_CY_ASYM,	/* asymmetric cipher/auth */
	WD_AT_CY_AUTH,	/* auth */
	WD_AT_CY_SYM_AUTH,	/* cipher/auth */
	WD_AT_CY_AUTH_SYM,	/* auth/cipher */
	WD_AT_CY_KEX,		/* key exchange */
	WD_AT_BNUM,		/* big number calculate */
	WD_AT_DCOMP,		/* data de-compression */
	WD_AT_DRBG,

	WD_AT_DUMMY_MEMCPY,   /* just for testing */

	WD_AT_ALG_TYPE_MAX,
};

/* Notes: The throughput and delay of queue as it doing the corresponding algorithm.
* The standard value is based on mainstream X86 CPU throughput, which is '10'.
* The driver guys should know the value of his engine while compared with
* mainstream X86 CPU core. Of cource, this real value will change as X86 CPU is
* developing. So, the mainstream X86 CPU version is based on the WD version
* releasing time.(fixme: this text should be removed finally)
*/

/* The throughput requirement is a value from 1 to 100, default to 10
 * bigger is higher
 */
typedef __u8 wd_throughput_level_t;

/* The latency requirement is a value from 1 to 100, default to 10
 * and the smaller value is, the delay is shorter.
 */
typedef __u8 wd_latency_level_t;


/* Flat memory, user cares for */
#define WD_CAPA_MEMS_FLAT			1

/* SGL memory, user cares for */
#define WD_CAPA_MEMS_SGL			2

/* SVM is supported with virtual address DMA, user cares for */
#define WD_CAPA_SVM_DMA			4

#endif
