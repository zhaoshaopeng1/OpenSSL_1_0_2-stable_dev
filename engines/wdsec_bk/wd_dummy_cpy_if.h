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

#ifndef __WD_DUMMY_CPY_IF_H
#define __WD_DUMMY_CPY_IF_H

/* Algorithm name */
#define memcopy			"memcopy"

/* algorithm parameter which is of WD */
struct wd_dummy_cpy_param {
	int max_copy_size;
};

#endif
