// SPDX-License-Identifier: GPL-2.0
/* See module.c for license details. */

#include "pmfs2.h"

#define BUILD_BUG_ON_NOTEQ(a_, b_) \
	BUILD_BUG_ON(a_ != b_)

#define BUILD_BUG_ON_SIZEOF(type_, size_) \
	BUILD_BUG_ON_NOTEQ(sizeof(type_), size_)

#define BUILD_BUG_ON_OFFSETOF(type_, member_, size_) \
	BUILD_BUG_ON_NOTEQ(offsetof(type_, member_), size_)

#define BUILD_BUG_ON_FIELD(pi_, zi_, m_) \
	do { \
		BUILD_BUG_ON_NOTEQ(offsetof(typeof(*pi_), m_), \
				   offsetof(typeof(*zi_), m_)); \
		BUILD_BUG_ON_NOTEQ(sizeof(pi_->m_), sizeof(zi_->m_)); \
	} while (0)

static void _verify_inode(void)
{
	struct pmfs2_inode *pi = NULL;
	struct zus_inode *zi = NULL;

	BUILD_BUG_ON(sizeof(*pi) < sizeof(*zi));
	BUILD_BUG_ON_FIELD(pi, zi, i_flags);
	BUILD_BUG_ON_FIELD(pi, zi, i_mode);
	BUILD_BUG_ON_FIELD(pi, zi, i_nlink);
	BUILD_BUG_ON_FIELD(pi, zi, i_size);
	BUILD_BUG_ON_FIELD(pi, zi, i_blocks);
	BUILD_BUG_ON_FIELD(pi, zi, i_mtime);
	BUILD_BUG_ON_FIELD(pi, zi, i_ctime);
	BUILD_BUG_ON_FIELD(pi, zi, i_atime);
	BUILD_BUG_ON_FIELD(pi, zi, i_ino);
	BUILD_BUG_ON_FIELD(pi, zi, i_uid);
	BUILD_BUG_ON_FIELD(pi, zi, i_gid);
	BUILD_BUG_ON_FIELD(pi, zi, i_xattr);
	BUILD_BUG_ON_FIELD(pi, zi, i_generation);
	BUILD_BUG_ON_FIELD(pi, zi, i_rdev);
	BUILD_BUG_ON_FIELD(pi, zi, i_symlink);
}

static void _verify_types(void)
{
	BUILD_BUG_ON_SIZEOF(struct pmfs2_dirent, PMFS2_DIRENT_SIZE);
	BUILD_BUG_ON_OFFSETOF(struct pmfs2_dirent, name,
			      PMFS2_DIRENT_META_SIZE);
	BUILD_BUG_ON_SIZEOF(struct pmfs2_inode, PMFS2_INODE_SIZE);
	BUILD_BUG_ON_SIZEOF(struct pmfs2_dirents_block, PMFS2_BLOCK_SIZE);
	BUILD_BUG_ON_SIZEOF(union pmfs2_meta_block, PMFS2_BLOCK_SIZE);
	BUILD_BUG_ON_SIZEOF(struct page, PMFS2_CL_SIZE);
}

static void _verify_persistent_structs(void)
{
	_verify_inode();
	_verify_types();
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

static ulong pmfs2_t1_free(struct super_block *sb)
{
	return PMFS2_SB(sb)->s_free_pages_list.size;
}

/*. . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . . .*/

struct pmfs2_inode *pmfs2_find_by_ino_it(struct super_block *sb,
					 struct pmfs2_inode *it, ulong ino)
{
	struct pmfs2_inode *pi;
	ulong index, islot;

	index = ino / PMFS2_INODES_PER_BLOCK;
	pi = pmfs2_find_data_block(sb, it, index);
	if (unlikely(!pi))
		return NULL;

	islot = ino % PMFS2_INODES_PER_BLOCK;
	return pi + islot;
}

static int _sbi_init_locks(struct pmfs2_sb_info *sbi)
{
	int err;
	size_t i;

	err = mutex_init(&sbi->s_lock);
	if (err)
		return err;

	err = mutex_init(&sbi->s_it_lock);
	if (err)
		return err;

	for (i = 0; i < ARRAY_SIZE(sbi->s_pi_lock); ++i) {
		err = mutex_init(&sbi->s_pi_lock[i]);
		if (err)
			return err;
	}
	return 0;
}

static void _sbi_fini_locks(struct pmfs2_sb_info *sbi)
{
	size_t i;

	mutex_fini(&sbi->s_lock);
	mutex_fini(&sbi->s_it_lock);

	for (i = 0; i < ARRAY_SIZE(sbi->s_pi_lock); ++i)
		mutex_fini(&sbi->s_pi_lock[i]);
}

int pmfs2_sbi_init(struct super_block *sb, struct pmfs2_sb_info *sbi,
		   struct multi_devices *md)
{
	int err;

	_verify_persistent_structs();

	sbi->sb = sb;
	sbi->s_mount_mkfs = false;
	list_init(&sbi->s_free_inodes);

	err = _sbi_init_locks(sbi);
	if (unlikely(err))
		return err;

	err = pmfs2_init_free_list(sb);
	if (unlikely(err))
		return err;

	pmfs2_populate_all_freeq(sb);

	err = pmfs2_pi_it_init(sb);
	if (unlikely(err))
		return err;

	return 0;
}

int pmfs2_sbi_statfs(struct super_block *sb, struct statfs64 *st)
{
	struct pmfs2_inode *it_pi = pmfs2_inode_table(sb);
	struct pmfs2_sb_info *sbi = PMFS2_SB(sb);

	st->f_type = PMFS2_SUPER_MAGIC;
	st->f_bsize = PMFS2_BLOCK_SIZE;
	st->f_namelen = PMFS2_NAME_MAX;
	st->f_blocks = pmfs2_t1_blocks(sb);
	st->f_bfree = st->f_bavail = pmfs2_t1_free(sb);
	st->f_files = pmfs2_pi_i_size(it_pi);
	st->f_ffree = sbi->s_free_inodes_count;

	pmfs2_dbg_vfs("blocks=0x%lx bfree=0x%lx files=0x%lx ffree=0x%lx\n",
		      st->f_blocks, st->f_bfree, st->f_files, st->f_ffree);
	return 0;
}

void pmfs2_sbi_fini(struct super_block *sb)
{
	struct pmfs2_sb_info *sbi = PMFS2_SB(sb);

	if (unlikely(!sbi))
		return;

	_sbi_fini_locks(sbi);
	pmfs2_fini_free_list(sb);
}

int pmfs2_sbi_recon(struct super_block *sb, struct inode *root_i)
{
	/* Doing 'mkfs' upon first mount, no need for recon */
	if (unlikely(PMFS2_SB(sb)->s_mount_mkfs))
		return 0;

	return pmfs2_reconstruct(sb, root_i);
}
