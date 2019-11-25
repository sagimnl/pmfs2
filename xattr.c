// SPDX-License-Identifier: GPL-2.0
/* See module.c for license details. */
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include "pmfs2.h"


ssize_t pmfs2_getxattr(struct super_block *sb, struct inode *inode, int type,
		       const char *name, void *buffer, size_t size)
{
	return -ENOTSUP;
}

int pmfs2_setxattr(struct super_block *sb, struct inode *inode, int type,
		   const char *name, const void *value, size_t size, int flags)
{
	return -ENOTSUP;
}


ssize_t pmfs2_listxattr(struct super_block *sb, struct inode *inode,
			char *buffer, size_t size, bool trusted)
{
	return -ENOTSUP;
}
