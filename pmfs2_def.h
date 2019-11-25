/* SPDX-License-Identifier: GPL-2.0 */
/* See module.c for license details. */
#ifndef _PMFS2_DEF_H_
#define _PMFS2_DEF_H_

#include <zus.h>
#include "md_def.h"

/* global defs */
#define PMFS2_SUPER_MAGIC       0x504D4653 /* ASCII "PMFS2" */
#define PMFS2_MAJOR_VERSION     1
#define PMFS2_MINOR_VERSION     0
#define PMFS2_CL_SIZE           64 /* cache-line size */
#define PMFS2_NAME_MAX          255 /* not including null */
#define PMFS2_BLOCK_SHIFT       PAGE_SHIFT
#define PMFS2_BLOCK_SIZE        PAGE_SIZE
#define PMFS2_PTR_SHIFT         3 /* 8-bytes __le64 block pointer */
#define PMFS2_PTR_SIZE          (1 << PMFS2_PTR_SHIFT)

#define PMFS2_BTREE_HEIGHT_MAX  4
#define PMFS2_META_SHIFT        (PMFS2_BLOCK_SHIFT - PMFS2_PTR_SHIFT)
#define PMFS2_META_MASK         ((1 << PMFS2_META_SHIFT) - 1)
#define PMFS2_META_LEVEL_SIZE   (1 << PMFS2_META_SHIFT)

#define PMFS2_INODE_SIZE        128
#define PMFS2_INODES_PER_BLOCK  (PMFS2_BLOCK_SIZE / PMFS2_INODE_SIZE)

#define PMFS2_ROOT_INO          1
#define PMFS2_DIRENT_SIZE       16
#define PMFS2_DIRENT_META_SIZE  12
#define PMFS2_LINK_MAX          ZUFS_LINK_MAX


/* "on-pmem" data structures */
struct pmfs2_dirent {
	__le64	ino;
	u8	nde;
	u8	nde_prev;
	u8	name_len;
	u8	file_type;
	char	name[4];
};


struct pmfs2_dirents_block {
	__le64 next;
	__le64 base_off;
	struct pmfs2_dirent de[255];
};


struct pmfs2_inode {
	__le16	i_flags;
	__le16	i_mode;
	__le32	i_nlink;
	__le64	i_size;
	struct {
		__le64	root;
		u8	height;
		u8	_pad[7];
	} i_btree;
	__le64	i_blocks;
	__le64	i_mtime;
	__le64	i_ctime;
	__le64	i_atime;
	/* 64 - cache-line boundary */
	__le64	i_ino;
	__le32	i_uid;
	__le32	i_gid;
	__le64	i_xattr;
	__le64	i_generation;
	union {
		__le32	i_rdev;
		u8	i_symlink[32];
		struct {
			__le64	i_sym_dpp;
			__le64	i_sym_bn;
		};
		struct {
			__le64	i_dir_ndents;
			__le64	i_dir_parent;
		};
		struct {
			__le64	reserved;
			struct a_list_head i_lh;
		};
	};
};

struct pmfs2_super_block {
	struct md_dev_table	s_mdt;
	struct pmfs2_inode	s_itable;
};

union pmfs2_meta_block {
	struct md_dev_table mdt;
	struct pmfs2_super_block sb;
	struct pmfs2_dirents_block db;
	u8 _b[PMFS2_BLOCK_SIZE];
};

#endif /* _PMFS2_DEF_H_ */
