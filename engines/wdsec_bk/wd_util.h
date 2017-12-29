/*
 * Copyright (c) 2017. Hisilicon Tech Co. Ltd. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

/* the common drv header define the unified interface for wd */
#ifndef __WD_UTIL_H__
#define __WD_UTIL_H__

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/epoll.h>
#include <sys/eventfd.h>

#include "../../include/uapi/linux/vfio.h"
#include "../../drivers/crypto/hisilicon/wd/wd_drv_io_if.h"
#include "wd.h"


/*
#define WD_MDEV_GROUP_PATH	"/sys/bus/mdev/devices/%s/iommu_group"*/
#define WD_VFIO_NOIOMMU_SW \
		"/sys/module/vfio/parameters/enable_unsafe_noiommu_mode"
		



#ifndef  WD_ERR
#define WD_ERR(format, args...) printf(format, ##args)
#endif

static inline int _wd_syscall(struct wd_queue *q, int id, void *para) {

	if (q->device <= 0) {
		errno = -ENODEV;
		return -ENODEV;
	}

	return ioctl(q->device, id, para);
}

static inline void wd_reg_write(void *reg_addr, uint32_t value)
{
	*((volatile uint32_t *)reg_addr) = value;
}
static inline uint32_t wd_reg_read(void *reg_addr)
{
	uint32_t temp;
	
	temp = *((volatile uint32_t *)reg_addr);

	return temp;
}
void *wd_map(unsigned long long addr, uint32_t size);
void wd_unmap(void *addr, uint32_t size);
int wd_get_mdev_zinfo(int device, struct wd_azone *info, int num);
void wd_put_mdev_zinfo(int device, struct wd_azone *info, int num);
int wd_set_mdev_irq(int device, int irq_index, int count, int action);
int wd_unset_mdev_irq(int device, int irq_index);
int wd_get_paddr(const void *virtaddr,	unsigned long long *paddr);
int wd_write_sysfs_file(const char *path, char *buf, int size);
int wd_get_dma_zone(struct wd_queue *q, struct wd_azone *zone);
int wd_put_dma_zone(struct wd_queue *q, struct wd_azone *zone);
#endif
