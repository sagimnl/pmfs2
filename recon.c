// SPDX-License-Identifier: GPL-2.0
/* See module.c for license details. */

#include "pmfs2.h"

struct pmfs2_recon_info {
	struct super_block *sb;
	struct pmfs2_sb_info *sbi;
	struct pmfs2_inode *root_pi;
	ulong num_inodes;
};

static void _init_recon_info(struct pmfs2_recon_info *pri,
			     struct super_block *sb, struct inode *root_i)
{
	pri->sb = sb;
	pri->sbi = PMFS2_SB(sb);
	pri->root_pi = PMFS2_I(root_i)->pi;
	pri->num_inodes = 0;
}

static int _recon_itable_root(struct pmfs2_recon_info *pri)
{
	struct pmfs2_inode *it_pi, *root_pi;
	struct pmfs2_sb_info *sbi = pri->sbi;
	int err;

	it_pi = pmfs2_inode_table(pri->sb);
	if (unlikely(it_pi->i_btree.height > PMFS2_BTREE_HEIGHT_MAX))
		return -EFSCORRUPTED;

	err = pmfs2_btree_recon(pri->sb, it_pi);
	if (unlikely(err))
		return err;

	root_pi = pmfs2_find_by_ino_it(pri->sb, it_pi, PMFS2_ROOT_INO);
	if (unlikely(!root_pi))
		return -EFSCORRUPTED;

	err = pmfs2_pi_recon(pri->sb, root_pi);
	if (unlikely(err))
		return err;

	sbi->s_itable_pi = it_pi;
	sbi->s_root_pi = root_pi;
	return 0;
}

static ulong _itable_ino_max(struct pmfs2_inode *it_pi)
{
	ulong size;

	size = pmfs2_pi_i_size(it_pi);
	return pmfs2_o2b_up(size) * PMFS2_INODES_PER_BLOCK;
}

static int _recon_inodes(struct pmfs2_recon_info *pri)
{
	struct pmfs2_inode *it_pi = pmfs2_inode_table(pri->sb);
	struct pmfs2_inode *pi;
	ulong ino, ino_max;
	int err = 0;

	ino_max = _itable_ino_max(it_pi);
	for (ino = PMFS2_ROOT_INO; (ino < ino_max) && !err; ++ino) {
		pi = pmfs2_pi_find_by_ino(pri->sb, ino);
		BUG_ON(!pi);
		BUG_ON(!pi->i_ino);

		if (pmfs2_pi_active(pi))
			err = pmfs2_pi_recon(pri->sb, pi);
		else
			pmfs2_enq_free_inode(pri->sb, pi);

	}
	return err;
}

int pmfs2_reconstruct(struct super_block *sb, struct inode *root_i)
{
	struct pmfs2_recon_info pri;
	int err;

	_init_recon_info(&pri, sb, root_i);

	err = _recon_itable_root(&pri);
	if (unlikely(err))
		return err;

	err = _recon_inodes(&pri);
	if (unlikely(err))
		return err;

	return 0;
}


