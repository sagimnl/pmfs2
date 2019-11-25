// SPDX-License-Identifier: GPL-2.0
/* See module.c for license details. */
#define _GNU_SOURCE
#include <sys/types.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdbool.h>
#include "pmfs2.h"


static long _div_s64_rem(long dividend, int divisor, int *remainder)
{
	*remainder = dividend % divisor;
	return dividend / divisor;
}

void pmfs2_le64_to_timespec(struct timespec *ts, __le64 *t)
{
	int nsec;

	ts->tv_sec = _div_s64_rem(le64_to_cpu(*t), NSEC_PER_SEC, &nsec);
	ts->tv_nsec = nsec;
}

void pmfs2_timespec_to_le64(__le64 *t, struct timespec *ts)
{
	*t = cpu_to_le64(ts->tv_sec * NSEC_PER_SEC + ts->tv_nsec);
}

bool pmfs2_pi_active(struct pmfs2_inode *pi)
{
	return (le32_to_cpu(pi->i_nlink) > 0);
}

void pmfs2_flush_pi(struct super_block *sb, struct pmfs2_inode *pi)
{
	pmfs2_flush_buffer(pi, sizeof(*pi));
	(void)sb;
}

void pmfs2_pii_init_once(struct pmfs2_inode_info *pii,
			 struct pmfs2_sb_info *sbi)
{
	pii->sbi = sbi;
	pii->pi = NULL;
}

void *pmfs2_find_data_block(struct super_block *sb,
			    struct pmfs2_inode *pi, ulong index)
{
	struct pmfs2_gbi gbi = {};
	int err;

	err = pmfs2_get_data_block(sb, pi, index, 0, &gbi);
	if (unlikely(err))
		return NULL;

	return pmfs2_baddr(sb, gbi.bn);
}

ulong pmfs2_pi_ino(struct pmfs2_inode *pi)
{
	return zi_ino(PZI(pi));
}

static void _pi_reset_inode(struct pmfs2_inode *pi, bool active)
{
	if (active)
		pi->i_nlink = cpu_to_le32(1);
}

uint pmfs2_pi_mode(struct pmfs2_inode *pi)
{
	return le16_to_cpu(pi->i_mode);
}

ulong pmfs2_pi_i_size(struct pmfs2_inode *pi)
{
	return le64_to_cpu(pi->i_size);
}

void pmfs2_pi_size_add(struct pmfs2_inode *pi, ulong n)
{
	pmfs2_pi_set_size(pi, pmfs2_pi_i_size(pi) + n);
}

void pmfs2_pi_size_dec(struct pmfs2_inode *pi, ulong n)
{
	pmfs2_pi_set_size(pi, pmfs2_pi_i_size(pi) - n);
}

void pmfs2_pi_set_size(struct pmfs2_inode *pi, ulong isize)
{
	pi->i_size = cpu_to_le64(isize);
}

ulong pmfs2_pi_blocks(struct pmfs2_inode *pi)
{
	return le64_to_cpu(pi->i_blocks);
}

void pmfs2_pi_blocks_set(struct pmfs2_inode *pi, ulong n)
{
	pi->i_blocks = cpu_to_le64(n);
}

void pmfs2_pi_blocks_add(struct pmfs2_inode *pi, ulong n)
{
	pmfs2_pi_blocks_set(pi, pmfs2_pi_blocks(pi) + n);
}

void pmfs2_pi_blocks_dec(struct pmfs2_inode *pi, ulong n)
{
	pmfs2_pi_blocks_set(pi, pmfs2_pi_blocks(pi) - n);
}

void pmfs2_pi_nlink_add(struct pmfs2_inode *pi)
{
	le32_add_cpu(&pi->i_nlink, 1);
}

void pmfs2_pi_nlink_dec(struct pmfs2_inode *pi)
{
	le32_add_cpu(&pi->i_nlink, -1);
}

void pmfs2_pi_set_pii(struct inode *inode, struct pmfs2_inode *pi)
{
	struct pmfs2_inode_info *pii = PMFS2_I(inode);

	pii->pi = pi;
	pii->flags = 0;
}

struct pmfs2_inode *pmfs2_pi_find_by_ino(struct super_block *sb, ulong ino)
{
	return pmfs2_find_by_ino_it(sb, pmfs2_inode_table(sb), ino);
}

void pmfs2_pi_lock(struct super_block *sb, struct pmfs2_inode *pi)
{
	size_t lock_index;
	struct pmfs2_sb_info *sbi = PMFS2_SB(sb);

	lock_index = (long)pi % ARRAY_SIZE(sbi->s_pi_lock);
	mutex_lock(&sbi->s_pi_lock[lock_index]);
}

void pmfs2_pi_unlock(struct super_block *sb, struct pmfs2_inode *pi)
{
	size_t lock_index;
	struct pmfs2_sb_info *sbi = PMFS2_SB(sb);

	lock_index = (long)pi % ARRAY_SIZE(sbi->s_pi_lock);
	mutex_unlock(&sbi->s_pi_lock[lock_index]);
}

int pmfs2_pi_alloc_blocks(struct super_block *sb, struct pmfs2_inode *pi,
			  ulong index, uint num, uint flags)
{
	int err;

	pmfs2_pi_lock(sb, pi);

	err = pmfs2_btree_alloc_blocks(sb, pi, index, num, flags);

	pmfs2_pi_unlock(sb, pi);

	return err;
}

static void pmfs2_it_lock(struct super_block *sb)
{
	mutex_lock(&PMFS2_SB(sb)->s_it_lock);
}
static void pmfs2_it_unlock(struct super_block *sb)
{
	mutex_unlock(&PMFS2_SB(sb)->s_it_lock);
}

void pmfs2_enq_free_inode(struct super_block *sb, struct pmfs2_inode *pi)
{
	struct pmfs2_sb_info *sbi = PMFS2_SB(sb);
	ulong ino = pmfs2_pi_ino(pi);

	if (unlikely(ino <= PMFS2_ROOT_INO))
		return;

	pi->i_nlink = 0;
	list_init(&pi->i_lh);
	list_add_tail(&pi->i_lh, &sbi->s_free_inodes);
	sbi->s_free_inodes_count++;
}

static void _add_free_inode(struct super_block *sb,
			    struct pmfs2_inode *pi)
{
	pmfs2_it_lock(sb);

	pmfs2_enq_free_inode(sb, pi);

	pmfs2_it_unlock(sb);
}

static int __increase_inode_table_size(struct super_block *sb)
{
	struct pmfs2_inode *it_pi = pmfs2_inode_table(sb);
	struct pmfs2_inode *pi;
	struct pmfs2_gbi gbi = {};
	ulong base_ino, index;
	int err, i = 0;

	index = pmfs2_o2b(pmfs2_pi_i_size(it_pi));
	err = pmfs2_pi_alloc_blocks(sb, it_pi, index, 1, 0);
	if (unlikely(err)) {
		pmfs2_dbg_err("index=%lu err=%d\n", index, err);
		return err;
	}

	pmfs2_pi_set_size(it_pi, pmfs2_b2o(index + 1));
	pmfs2_flush_pi(sb, it_pi);

	err = pmfs2_get_data_block(sb, it_pi, index, 0, &gbi);
	if (unlikely(err)) {
		pmfs2_dbg_err("index=%lu err=%d\n", index, err);
		return err;
	}

	base_ino = index * PMFS2_INODES_PER_BLOCK;
	pi = pmfs2_baddr(sb, gbi.bn);
	if (index == 0) {
		i = 1;
		++pi;
	}
	for (; i < PMFS2_INODES_PER_BLOCK; ++i, ++pi) {
		pi->i_ino = cpu_to_le64(base_ino + i);
		pmfs2_enq_free_inode(sb, pi);
	}
	return 0;
}

static int _increase_inode_table_size(struct super_block *sb)
{
	int err;

	pmfs2_it_lock(sb);

	err = __increase_inode_table_size(sb);

	pmfs2_it_unlock(sb);

	return err;
}

static int _init_root_inode(struct super_block *sb, struct pmfs2_inode *it_pi)
{
	struct pmfs2_inode *pi = pmfs2_pi_find_by_ino(sb, PMFS2_ROOT_INO);

	if (unlikely(!pi))
		return -EFSCORRUPTED;

	pi->i_nlink = cpu_to_le32(2);
	pi->i_mode = it_pi->i_mode | cpu_to_le16(S_IFDIR);
	pi->i_uid = it_pi->i_uid;
	pi->i_gid = it_pi->i_gid;
	pi->i_atime = it_pi->i_atime;
	pi->i_mtime = it_pi->i_mtime;
	pi->i_ctime = it_pi->i_ctime;
	pmfs2_init_new_dir(pi, 0);

	pmfs2_flush_pi(sb, pi);
	return 0;
}

int pmfs2_pi_it_init(struct super_block *sb)
{
	struct pmfs2_sb_info *sbi = PMFS2_SB(sb);
	struct pmfs2_inode *it_pi = pmfs2_inode_table(sb);
	int err;

	/* re-mount case */
	if (pmfs2_pi_blocks(it_pi))
		return 0;

	/* first-mount case: mkfs */
	sbi->s_mount_mkfs = true;
	err = _increase_inode_table_size(sb);
	if (unlikely(err))
		return err;

	return _init_root_inode(sb, it_pi);
}

static struct pmfs2_inode *_new_free_inode(struct super_block *sb)
{
	struct pmfs2_sb_info *sbi = PMFS2_SB(sb);
	struct pmfs2_inode *pi;
	int err = 0;

	pmfs2_it_lock(sb);

	if (unlikely(!sbi->s_free_inodes_count)) {
		err = __increase_inode_table_size(sb);
		if (unlikely(err)) {
			pmfs2_it_unlock(sb);
			return ERR_PTR(err);
		}
	}

	pi = list_first_entry(&sbi->s_free_inodes, typeof(*pi), i_lh);
	list_del_init(&pi->i_lh);
	sbi->s_free_inodes_count--;

	pmfs2_it_unlock(sb);

	_pi_reset_inode(pi, true);
	return pi;
}

struct pmfs2_inode *pmfs2_pi_new(struct super_block *sb, bool is_dir,
				 ulong parent_ino, const char *symname)
{
	struct pmfs2_inode *pi = NULL;
	int err;

	pi = _new_free_inode(sb);
	if (IS_ERR(pi))
		return pi;

	pi->i_nlink = cpu_to_le32(1);
	pi->i_xattr = 0;

	if (symname) {
		err = pmfs2_symlink_create(sb, pi, symname);
		if (unlikely(err))
			goto fail;
	} else if (is_dir) {
		pmfs2_dbg_vfs("[%ld] new dir parent_ino=%ld",
			      pmfs2_pi_ino(pi), parent_ino);
		pmfs2_init_new_dir(pi, parent_ino);
	}
	return pi;
fail:
	pi->i_nlink = 0;
	/* TODO: free pi */
	return ERR_PTR(err);
}

int pmfs2_pi_setattr(struct super_block *sb, struct inode *inode)
{
	struct pmfs2_inode *pi = pmfs2_pi(inode);

	/*
	 * zus_inode and pmfs2_inode are the same, so just do flush
	 */
	pmfs2_flush_pi(sb, pi);
	return 0;
}

void pmfs2_pi_truncate_size(struct super_block *sb, struct inode *inode,
			    loff_t size)
{
	struct pmfs2_inode_info *pii = PMFS2_I(inode);
	struct pmfs2_inode *pi = pii->pi;

	if ((ulong)size != pmfs2_pi_i_size(pi)) {
		ulong index = pmfs2_o2b_up(size);

		pmfs2_btree_truncate(sb, pi, index, pmfs2_pi_i_size(pi));
		pmfs2_pi_set_size(pi, (ulong)size);
		pmfs2_flush_pi(sb, pi);
	}
}

void pmfs2_pi_free(struct super_block *sb, struct inode *inode)
{
	struct pmfs2_inode *pi = pmfs2_pi(inode);
	ulong ino = pmfs2_pi_ino(pi);

	pmfs2_dbg_vfs("[%lu] pi=%p\n", ino, pi);

	if (unlikely(ino == PMFS2_ROOT_INO)) {
		WARN_ON(1);
		return;
	}
	if (_pi_isreg(pi))
		pmfs2_pi_truncate_size(sb, inode, 0);
	else if (_pi_islnk(pi))
		pmfs2_symlink_remove(sb, inode);

	_pi_reset_inode(pi, false);
	_add_free_inode(sb, pi);
}

int pmfs2_pi_sync(struct super_block *sb, struct inode *inode,
		  loff_t start, loff_t uend, int datasync)
{
	struct pmfs2_inode_info *pii = PMFS2_I(inode);

	pmfs2_dbg_vfs("[%ld] start=0x%lx uend=0x%lx datasync=%d\n",
		      pmfs2_pi_ino(pii->pi), start, uend, datasync);
	/* TODO: iterate and cl_flush all the range for mmap */
	return 0;
}

loff_t pmfs2_pi_lseek_data_hole(struct super_block *sb, struct inode *inode,
				loff_t offset, int whence)
{
	return -ENOTSUP;
}

int pmfs2_pi_recon(struct super_block *sb, struct pmfs2_inode *pi)
{
	int err;

	err = pmfs2_mark_addr_active(sb, pi);
	if (unlikely(err))
		return err;

	if (_pi_isreg(pi))
		err = pmfs2_btree_recon(sb, pi);
	else if (_pi_isdir(pi))
		err = pmfs2_dir_recon(sb, pi);
	else if (_pi_islnk(pi))
		err = pmfs2_symlink_recon(sb, pi);

	return err;
}
