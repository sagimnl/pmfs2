// SPDX-License-Identifier: GPL-2.0
/* See module.c for license details. */
#include "pmfs2.h"

int pmfs2_symlink_create(struct super_block *sb, struct pmfs2_inode *pi,
			 const char *symname)
{
	char *sym;
	ulong bn, len;
	int err;

	len = strlen(symname);
	if (len < sizeof(pi->i_symlink)) {
		sym = (char *)(pi->i_symlink);
		pi->i_sym_dpp = 0;
		pi->i_sym_bn = 0;
	} else if (len < PMFS2_BLOCK_SIZE) {
		err = pmfs2_new_block(sb, &bn, true);
		if (unlikely(err))
			return err;

		sym = pmfs2_baddr(sb, bn);
		pi->i_sym_dpp = cpu_to_le64(pmfs2_addr_to_off(sb, sym));
		pi->i_sym_bn = cpu_to_le64(bn);
	} else {
		/* TODO: FIXME */
		pmfs2_dbg_err("illegal symname len=%lu\n", len);
		return -ENOTSUP;
	}
	pi->i_size = cpu_to_le64(len);
	pmem_memmove_persist(sym, symname, len);
	sym[len] = '\0';

	pmfs2_flush_pi(sb, pi);
	return 0;
}

void pmfs2_symlink_remove(struct super_block *sb, struct inode *inode)
{
	struct pmfs2_inode *pi = pmfs2_pi(inode);
	ulong bn, i_size = pmfs2_pi_i_size(pi);

	if (unlikely(!i_size))
		return;

	if (i_size < sizeof(pi->i_symlink))
		goto out;

	bn = le64_to_cpu(pi->i_sym_bn);
	if (WARN_ON(!bn))
		return;

	pmfs2_free_block(sb, bn);
out:
	pi->i_size = 0;
	pi->i_sym_dpp = 0;
	pi->i_sym_bn = 0;
	pmfs2_flush_pi(sb, pi);
}

int pmfs2_symlink_recon(struct super_block *sb, struct pmfs2_inode *pi)
{
	ulong bn, i_size = pmfs2_pi_i_size(pi);
	char *sym;
	int err;

	if (i_size < sizeof(pi->i_symlink))
		return 0;

	bn = le64_to_cpu(pi->i_sym_bn);
	if (unlikely(!bn))
		return -EFSCORRUPTED;

	err =  pmfs2_mark_bn_active(sb, bn);
	if (err)
		return err;

	sym = pmfs2_baddr(sb, bn);
	pi->i_sym_dpp = cpu_to_le64(pmfs2_addr_to_off(sb, sym));
	pmfs2_flush_pi(sb, pi);

	return 0;
}
