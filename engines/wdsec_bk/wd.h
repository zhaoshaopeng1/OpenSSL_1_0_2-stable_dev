/*
 * Copyright (c) 2017. Hisilicon Tech Co. Ltd. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef __WD_H
#define __WD_H
#include <stdlib.h>
#include <errno.h>
//#include <sysfs/libsysfs.h>
#include "./dependency/libsysfs.h"
#include "vfio.h"

#define PATH_STR_SIZE SYSFS_PATH_MAX
#define WD_NAME_SIZE 64
#define WD_MAX_MEMLIST_SZ 128


#ifndef dma_addr_t
#define dma_addr_t __u64
#endif
#include "wd_usr_if.h"

typedef int bool;

#ifndef true
#define true 1
#endif

#ifndef false
#define false 0
#endif

/* the flags used by wd_capa->flags, the high 16bits are for algorithm and the low 16bits are for Framework */
#define WD_FLAGS_FW_PREFER_LOCAL_ZONE 1

#define WD_FLAGS_FW_MASK 0x0000FFFF

/* Memory in accelerating message can be different */
enum wd_addr_flags {
	WD_AATTR_INVALID = 0,

	 /* Common user virtual memory */
	_WD_AATTR_COM_VIRT = 1,

	 /* Physical address*/
	_WD_AATTR_PHYS = 2,

	/* I/O virtual address*/
	_WD_AATTR_IOVA = 4,

	/* SGL, user cares for */
	WD_AATTR_SGL = 8,

	/* Flat memory, user cares for */
	WD_AATTR_FLAT = 16,
};

#define WD_CAPA_PRIV_DATA_SIZE	64

/* Queue Capabilities header */
struct wd_capa {
	__u32 ver;
	char *alg;
	int throughput;
	int latency;
	__u32 flags;
	__u8 priv[WD_CAPA_PRIV_DATA_SIZE];
};

#define alloc_obj(objp) objp = malloc(sizeof(*objp))
#define free_obj(objp) if(objp)free(objp)
#define WD_ERR(format, args...) printf(format, ##args)

struct wd_queue;

struct wd_dma_ops {
	int (*dma_map)(struct wd_queue *q, void *p, int size);
	int (*dma_unmap)(struct wd_queue *q, __u64 p, int size);
};

struct wd_queue {
	char *dev_name;
	char *hw_type;
	int hw_type_id;
	struct wd_capa capa;
	void *priv; /* private data used by the drv layer */
	int container;
	int group;
	int device;
	void *alg_info;
	struct wd_dma_ops *dma_ops;
	char mdev_path[PATH_STR_SIZE];
	char iommu_lpath[PATH_STR_SIZE];
	char iommu_fpath[PATH_STR_SIZE];
	char iommu_name[PATH_STR_SIZE];
	char vfio_group_path[PATH_STR_SIZE];
};

struct mem_list {
	void *addr;
	size_t len;
	__u32 flags;
};

int wd_dump_all_algos(void);
int wd_request_queue(struct wd_queue *q, struct wd_capa *capa);
void wd_release_queue(struct wd_queue *q);
int wd_send(struct wd_queue *q, void *req);
int wd_recv(struct wd_queue *q, void **resp);
int wd_wait(struct wd_queue *q, int ms_timeout);
int wd_mem_share(struct wd_queue *q, struct mem_list *memlist);
void wd_mem_unshare(struct wd_queue *q, struct mem_list *memlist);

/* Zaibo: Add currently, i think it is necessary for legacy mode queue */
int wd_add_dma_ops(struct wd_queue *q, struct wd_dma_ops *ops);
void wd_del_dma_ops(struct wd_queue *q);

/* this is only for drv used */
int wd_set_queue_attr(struct wd_queue *q, const char *name, const char *value);
int __iommu_type(struct wd_queue *q);
#endif
