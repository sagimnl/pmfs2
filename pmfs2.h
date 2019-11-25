/* SPDX-License-Identifier: GPL-2.0 */
/* See module.c for license details. */
#ifndef _PMFS2_H_
#define _PMFS2_H_

#include <unistd.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdio.h>
#include <errno.h>
#include <pthread.h>
#include <zus.h>
#include <b-minmax.h>

#include "pmfs2_def.h"
#include "pmfs2_kinu.h"

struct pmfs2_gbi {
	struct zus_iomap_build *iomb;
	ulong bn;
	int rw;
};

struct pmfs2_list {
	spinlock_t lock;
	struct list_head lru;
	struct multi_devices *md;
	size_t size;
	size_t bn_max;
};

struct pmfs2_sb_info {
	struct zus_sb_info zsbi;
	struct super_block _sb;
	struct super_block *sb;
	struct pmfs2_list s_free_pages_list;
	struct multi_devices *md;
	struct pmfs2_inode *s_itable_pi;
	struct pmfs2_inode *s_root_pi;
	struct mutex s_lock; /* Lock for consistent statfs */
	struct mutex s_it_lock;
	struct mutex s_pi_lock[31];
	struct list_head s_free_inodes;
	ulong s_free_inodes_count;
	ulong s_mount_flags;
	bool  s_mount_mkfs;
};

struct pmfs2_inode_info {
	struct inode vfs_inode;
	struct zus_inode_info zii;
	struct pmfs2_sb_info *sbi;
	struct pmfs2_inode *pi;
	ulong flags;
};

struct pmfs2_readdir_ctx {
	struct zufs_readdir_iter rdi;
	ulong  cnt;
	loff_t pos;
};

/* debug trace */
enum pmfs2_trace_channel {
	PMFS2_TRACE_INFO,
	PMFS2_TRACE_WARN,
	PMFS2_TRACE_ERROR,
	PMFS2_TRACE_VFS,
	PMFS2_TRACE_RW,
	PMFS2_TRACE_RECON,
	PMFS2_TRACE_XATTR,
	PMFS2_TRACE_VERBOS
};

void pmfs2_pr(int dbg, enum pmfs2_trace_channel ch, const char *file, int line,
	      const char *func, const char *fmt, ...);

#define pmfs2_pr_(dbg, ch_, fmt_, ...) \
	pmfs2_pr(dbg, PMFS2_TRACE_##ch_, __FILE__, \
		 __LINE__, __func__, fmt_, __VA_ARGS__)

#define pmfs2_warn(fmt_, ...)           pmfs2_pr_(0, WARN, fmt_, __VA_ARGS__)
#define pmfs2_err(fmt_, ...)            pmfs2_pr_(0, ERROR, fmt_, __VA_ARGS__)
#define pmfs2_debug_(ch_, fmt_, ...)    pmfs2_pr_(1, ch_, fmt_, __VA_ARGS__)
#define pmfs2_dbg_info(fmt_, ...)       pmfs2_debug_(INFO, fmt_, __VA_ARGS__)
#define pmfs2_dbg_err(fmt_, ...)        pmfs2_debug_(ERROR, fmt_, __VA_ARGS__)
#define pmfs2_dbg_vfs(fmt_, ...)        pmfs2_debug_(VFS, fmt_, __VA_ARGS__)
#define pmfs2_dbg_rw(fmt_, ...)         pmfs2_debug_(RW, fmt_, __VA_ARGS__)
#define pmfs2_dbg_recon(fmt_, ...)      pmfs2_debug_(RECON, fmt_, __VA_ARGS__)
#define pmfs2_dbg_xattr(fmt_, ...)      pmfs2_debug_(XATTR, fmt_, __VA_ARGS__)
#define pmfs2_dbg_verbose(fmt_, ...)    pmfs2_debug_(VERBOS, fmt_, __VA_ARGS__)

static inline struct zus_inode *PZI(struct pmfs2_inode *pi)
{
	return (struct zus_inode *)pi;
}

static inline bool _pi_isdir(struct pmfs2_inode *pi)
{
	return 0 != S_ISDIR(le16_to_cpu(pi->i_mode));
}

static inline bool _pi_isreg(struct pmfs2_inode *pi)
{
	return 0 != S_ISREG(le16_to_cpu(pi->i_mode));
}

static inline bool _pi_islnk(struct pmfs2_inode *pi)
{
	return zi_islnk(PZI(pi));
}

/* type conversion helpers */
static inline struct pmfs2_sb_info *PSBI(struct zus_sb_info *zsbi)
{
	return container_of(zsbi, struct pmfs2_sb_info, zsbi);
}

static inline struct super_block *ZSB(struct zus_sb_info *sbi)
{
	return PSBI(sbi)->sb;
}

static inline struct pmfs2_inode_info *ZPII(struct zus_inode_info *zii)
{
	return container_of(zii, struct pmfs2_inode_info, zii);
}

static inline struct inode *ZVI(struct zus_inode_info *zii)
{
	return &ZPII(zii)->vfs_inode;
}

static inline struct zus_inode_info *VZII(struct inode *inode)
{
	return &container_of(inode, struct pmfs2_inode_info, vfs_inode)->zii;
}

static inline struct pmfs2_sb_info *PMFS2_SB(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline struct pmfs2_inode_info *PMFS2_I(struct inode *inode)
{
	return container_of(inode, struct pmfs2_inode_info, vfs_inode);
}

static inline struct pmfs2_inode *pmfs2_pi(struct inode *inode)
{
	return PMFS2_I(inode)->pi;
}

static inline ulong pmfs2_b2o(ulong bn)
{
	return bn << PMFS2_BLOCK_SHIFT;
}

static inline ulong pmfs2_o2b(ulong off)
{
	return off >> PMFS2_BLOCK_SHIFT;
}

static inline ulong pmfs2_o2b_up(ulong off)
{
	return pmfs2_o2b(off + PMFS2_BLOCK_SIZE - 1);
}

static inline void *pmfs2_addr(struct super_block *sb, ulong offset)
{
	return md_addr(PMFS2_SB(sb)->md, offset);
}

static inline void *pmfs2_baddr(struct super_block *sb, ulong bn)
{
	return pmfs2_addr(sb, pmfs2_b2o(bn));
}

static inline ulong pmfs2_addr_to_bn(struct super_block *sb, void *addr)
{
	return md_addr_to_bn(PMFS2_SB(sb)->md, addr);
}

static inline ulong pmfs2_addr_to_off(struct super_block *sb, void *addr)
{
	struct md_dev_info *mdi = md_t1_dev(PMFS2_SB(sb)->md, 0);

	if (unlikely(!mdi))
		return 0;

	return mdi->offset + (addr - mdi->t1i.virt_addr);
}

static inline struct pmfs2_super_block *pmfs2_msb(struct super_block *sb)
{
	return md_t1_addr(PMFS2_SB(sb)->md, 0);
}

static inline ulong pmfs2_t1_blocks(struct super_block *sb)
{
	return md_t1_blocks(PMFS2_SB(sb)->md);
}

static inline struct pmfs2_inode *pmfs2_inode_table(struct super_block *sb)
{
	return &pmfs2_msb(sb)->s_itable;
}

static inline void pmfs2_flush_buffer(void *buf, unsigned int len)
{
	cl_flush(buf, len);
}

static inline void pmfs2_pmemzero(void *buf, unsigned int len)
{
	memzero_nt(buf, len);
}

/* super.c */
int pmfs2_sbi_init(struct super_block *sb, struct pmfs2_sb_info *sbi,
		   struct multi_devices *md);
void pmfs2_sbi_fini(struct super_block *sb);
struct pmfs2_inode *pmfs2_find_by_ino_it(struct super_block *sb,
					 struct pmfs2_inode *it,
					 ulong ino);
int pmfs2_sbi_statfs(struct super_block *sb, struct statfs64 *st);
int pmfs2_sbi_recon(struct super_block *sb, struct inode *root_i);

/* recon.c */
int pmfs2_reconstruct(struct super_block *sb, struct inode *root_i);

/* inode.c */
void pmfs2_le64_to_timespec(struct timespec *ts, __le64 *t);
void pmfs2_timespec_to_le64(__le64 *t, struct timespec *ts);
bool pmfs2_pi_active(struct pmfs2_inode *pi);
void pmfs2_flush_pi(struct super_block *sb, struct pmfs2_inode *pi);
void pmfs2_pii_init_once(struct pmfs2_inode_info *pii,
			 struct pmfs2_sb_info *sbi);
void *pmfs2_find_data_block(struct super_block *sb,
			    struct pmfs2_inode *pi, ulong index);
void pmfs2_pi_set_pii(struct inode *inode, struct pmfs2_inode *pi);
int pmfs2_pi_it_init(struct super_block *sb);
struct pmfs2_inode *pmfs2_pi_find_by_ino(struct super_block *sb, ulong ino);
struct pmfs2_inode *pmfs2_pi_new(struct super_block *sb, bool is_dir,
				 ulong parent_ino, const char *symname);
int pmfs2_pi_alloc_blocks(struct super_block *sb, struct pmfs2_inode *pi,
			  ulong index, uint num, uint flags);
int pmfs2_pi_setattr(struct super_block *sb, struct inode *inode);
void pmfs2_pi_free(struct super_block *sb, struct inode *inode);
void pmfs2_pi_truncate_size(struct super_block *sb,
			    struct inode *inode, loff_t size);
int pmfs2_pi_sync(struct super_block *sb, struct inode *inode,
		  loff_t start, loff_t uend, int datasync);
loff_t pmfs2_pi_lseek_data_hole(struct super_block *sb, struct inode *inode,
				loff_t offset, int whence);
void pmfs2_enq_free_inode(struct super_block *sb, struct pmfs2_inode *pi);
int pmfs2_pi_recon(struct super_block *sb, struct pmfs2_inode *pi);

ulong pmfs2_pi_ino(struct pmfs2_inode *pi);
ulong pmfs2_pi_i_size(struct pmfs2_inode *pi);
uint pmfs2_pi_mode(struct pmfs2_inode *pi);
ulong pmfs2_pi_blocks(struct pmfs2_inode *pi);
void pmfs2_pi_size_add(struct pmfs2_inode *pi, ulong n);
void pmfs2_pi_size_dec(struct pmfs2_inode *pi, ulong n);
void pmfs2_pi_set_size(struct pmfs2_inode *pi, ulong isize);
void pmfs2_pi_blocks_set(struct pmfs2_inode *pi, ulong n);
void pmfs2_pi_blocks_add(struct pmfs2_inode *pi, ulong n);
void pmfs2_pi_blocks_dec(struct pmfs2_inode *pi, ulong n);
void pmfs2_pi_nlink_add(struct pmfs2_inode *pi);
void pmfs2_pi_nlink_dec(struct pmfs2_inode *pi);

void pmfs2_pi_lock(struct super_block *sb, struct pmfs2_inode *pi);
void pmfs2_pi_unlock(struct super_block *sb, struct pmfs2_inode *pi);

/* dir.c */
void pmfs2_init_new_dir(struct pmfs2_inode *pi, ulong parent_ino);
ulong pmfs2_de_ino(struct pmfs2_dirent *de);
struct pmfs2_dirent *
pmfs2_dir_lookup(struct super_block *sb, struct pmfs2_inode_info *dir_pii,
		 const struct qstr *name);
int pmfs2_dir_readdir(struct super_block *sb, struct inode *inode,
		      struct pmfs2_readdir_ctx *ctx);
int pmfs2_dir_add(struct super_block *sb, struct inode *dir,
		  const struct qstr *str, struct pmfs2_inode *pi);
int pmfs2_dir_remove(struct super_block *sb, struct inode *dir,
		     const struct qstr *name, struct inode *inode);
int pmfs2_dir_rename(struct super_block *sb, struct inode *old_dir,
		     struct inode *old_inode, struct qstr *old_name,
		     struct inode *new_dir, struct inode *new_inode,
		     struct qstr *new_name, uint flags);
int pmfs2_dir_recon(struct super_block *sb, struct pmfs2_inode *dir_pi);

/* rw.c */
ssize_t pmfs2_rw_read_iter(struct super_block *sb, struct inode *inode,
			   struct kiocb *kiocb, struct iov_iter *iter);
ssize_t pmfs2_rw_write_iter(struct super_block *sb, struct inode *inode,
			    struct kiocb *kiocb, struct iov_iter *ii);
ssize_t pmfs2_rw_get_multy_write(struct super_block *sb, struct inode *inode,
				 struct kiocb *kiocb, struct iov_iter *ii);
void pmfs2_rw_put_multy(struct super_block *sb, struct inode *inode,
			struct zufs_ioc_IO *io);
ssize_t pmfs2_rw_get_multy_read(struct super_block *sb, struct inode *inode,
				struct kiocb *kiocb, struct iov_iter *ii);
void pmfs2_mmap_close(struct inode *i);
int pmfs2_rw_fallocate(struct super_block *sb, struct inode *inode, int mode,
		       loff_t pos, loff_t end_pos, struct iov_iter *ii);

/* symlink.c */
int pmfs2_symlink_create(struct super_block *sb, struct pmfs2_inode *pi,
			 const char *symname);
void pmfs2_symlink_remove(struct super_block *sb, struct inode *inode);
int pmfs2_symlink_recon(struct super_block *sb, struct pmfs2_inode *pi);

/* xattr.c */
ssize_t pmfs2_getxattr(struct super_block *sb, struct inode *inode, int type,
		       const char *name, void *buffer, size_t size);
int pmfs2_setxattr(struct super_block *sb, struct inode *inode, int type,
		   const char *name, const void *value, size_t size, int flags);
ssize_t pmfs2_listxattr(struct super_block *sb, struct inode *inode,
			char *buffer, size_t size, bool trusted);

/* btree.c */
int pmfs2_get_data_block(struct super_block *sb, struct pmfs2_inode *pi,
			 ulong idx, uint flags, struct pmfs2_gbi *gbi);
void pmfs2_put_data_block(struct super_block *sb, struct pmfs2_gbi *gbi);
int pmfs2_btree_alloc_blocks(struct super_block *sb, struct pmfs2_inode *pi,
			     ulong idx, uint num, uint flags);
int pmfs2_get_block_create(struct super_block *sb, struct pmfs2_inode *pi,
			   ulong index, uint write_flags,
			   struct pmfs2_gbi *gbi);
void pmfs2_btree_truncate(struct super_block *sb, struct pmfs2_inode *pi,
			  ulong start, ulong end);
int pmfs2_btree_recon(struct super_block *sb, struct pmfs2_inode *pi);

/* balloc.c */
int pmfs2_new_block(struct super_block *sb, ulong *bn, bool zero);
void pmfs2_free_block(struct super_block *sb, ulong bn);
int pmfs2_init_free_list(struct super_block *sb);
void pmfs2_fini_free_list(struct super_block *sb);
void pmfs2_populate_all_freeq(struct super_block *sb);

int pmfs2_mark_bn_active(struct super_block *sb, ulong bn);
int pmfs2_mark_addr_active(struct super_block *sb, void *addr);

/* kinu.c */
void *pmfs2_malloc(size_t size);
void *pmfs2_calloc(size_t nmemb, size_t size);
void *pmfs2_zalloc(size_t size);
void pmfs2_free(void *ptr);

#endif /* _PMFS2_H_ */
