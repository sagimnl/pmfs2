// SPDX-License-Identifier: GPL-2.0
/* See module.c for license details. */
#define _GNU_SOURCE 1
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <dirent.h>
#include "pmfs2.h"

#ifndef RENAME_EXCHANGE
#define RENAME_EXCHANGE (1 << 1)
#endif



void pmfs2_init_new_dir(struct pmfs2_inode *pi, ulong parent_ino)
{
	pi->i_dir_parent = cpu_to_le64(parent_ino);
	pi->i_btree.root = 0;
	pi->i_dir_ndents = 0;
}

ulong pmfs2_de_ino(struct pmfs2_dirent *de)
{
	return le64_to_cpu(de->ino);
}

static bool _de_active(struct pmfs2_dirent *de)
{
	return pmfs2_de_ino(de) != 0;
}

static bool _de_name(struct pmfs2_dirent *de, const char *str, size_t len)
{
	return _de_active(de) && (de->name_len == len) &&
	       !memcmp(de->name, str, len);
}

static uint _de_size(struct pmfs2_dirent *de)
{
	return (uint)de->nde * PMFS2_DIRENT_SIZE;
}

static bool _de_space(struct pmfs2_dirent *de, uint name_len)
{
	return (_de_size(de) - PMFS2_DIRENT_META_SIZE) >= name_len;
}

static uint _de_count_for(uint name_len)
{
	uint nde = 1;
	uint len = PMFS2_DIRENT_META_SIZE + name_len;

	if (len > PMFS2_DIRENT_SIZE)
		nde = (len + PMFS2_DIRENT_SIZE - 1) / PMFS2_DIRENT_SIZE;

	return nde;
}

static struct pmfs2_dirent *_de_next(struct pmfs2_dirent *de)
{
	return de + de->nde;
}

static struct pmfs2_dirent *_de_other(struct pmfs2_dirent *de, long n)
{
	return de + n;
}

static struct pmfs2_dirent *
_de_lookup(struct pmfs2_dirents_block *deb, const char *str, size_t len)
{
	struct pmfs2_dirent *itr = deb->de;
	struct pmfs2_dirent *end = itr + ARRAY_SIZE(deb->de);

	while (itr < end) {
		if (_de_name(itr, str, len))
			return itr;
		itr = _de_next(itr);
	}
	return NULL;
}

static void _de_flush(struct pmfs2_dirent *de, u8 nde)
{
	pmfs2_flush_buffer(de, (unsigned int)nde * PMFS2_DIRENT_SIZE);
}

static struct pmfs2_dirent *
_de_add_split(struct pmfs2_dirent *de, struct pmfs2_dirent *de_end,
	      const struct qstr *str, ulong ino, u8 file_type)
{
	struct pmfs2_dirent *de_next, *de_tail;
	u8 old_nde = de->nde;

	de->ino = cpu_to_le64(ino);
	de->file_type = file_type;
	de->name_len = (u8)str->len;
	de->nde = _de_count_for(str->len);
	memcpy_to_pmem(de->name, str->name, de->name_len);

	de_next = _de_other(de, (long)old_nde);
	de_tail = _de_other(de, (long)de->nde);
	if (de_tail < de_next) {
		de_tail->ino = 0;
		de_tail->nde = old_nde - de->nde;
		de_tail->nde_prev = de->nde;
		de_tail->name_len = 0;
		de_tail->file_type = 0;
		_de_flush(de_tail, 1);

		if (de_next < de_end) {
			de_next->nde_prev = de_tail->nde;
			_de_flush(de_next, 1);
		}
	}
	_de_flush(de, de->nde);
	return de;
}

static void _de_clear(struct pmfs2_dirent *de)
{
	size_t nde = de->nde;

	de->ino = 0;
	de->file_type = 0;
	de->name_len = 0;
	memzero_nt(de->name, sizeof(de->name));
	if (likely(nde))
		memzero_nt(de + 1, (nde - 1) * sizeof(*de));
	_de_flush(de, 1);
}

static struct pmfs2_dirent *
_de_remove_merge(struct pmfs2_dirent *de, struct pmfs2_dirent *de_end)
{
	struct pmfs2_dirent  *de_prev, *de_next;

	de_prev = _de_other(de, -(long)de->nde_prev);
	de_next = _de_other(de, (long)de->nde);
	if ((de_prev < de) && !_de_active(de_prev)) {
		de_prev->nde += de->nde;
		de = de_prev;
	}
	if ((de_next < de_end) && !_de_active(de_next))
		de->nde += de_next->nde;

	de_next = _de_other(de, (long)de->nde);
	if (de_next < de_end) {
		de_next->nde_prev = de->nde;
		_de_flush(de_next, 1);
	}
	_de_clear(de);
	return de;
}

static long _dir_base_offset(struct pmfs2_dirents_block *deb)
{
	return le64_to_cpu(deb->base_off);
}

static loff_t _de_offset(struct pmfs2_dirents_block *deb,
			 struct pmfs2_dirent *de)
{
	return _dir_base_offset(deb) + (de - deb->de);
}

static loff_t _de_add(struct pmfs2_dirents_block *deb,
		      const struct qstr *str, ulong ino, u8 file_type)
{
	struct pmfs2_dirent *de = deb->de;
	struct pmfs2_dirent *end = de + ARRAY_SIZE(deb->de);
	loff_t de_off = -1;

	while (de < end) {
		if (!_de_active(de) && _de_space(de, str->len)) {
			de = _de_add_split(de, end, str, ino, file_type);
			de_off = _de_offset(deb, de);
			break;
		}
		de = _de_next(de);
	}
	return de_off;
}

static ulong _dir_next(struct pmfs2_dirents_block *deb)
{
	return le64_to_cpu(deb->next);
}

static ulong _dir_pi_root(struct pmfs2_inode *dir_pi)
{
	return le64_to_cpu(dir_pi->i_btree.root);
}

static ulong _dir_root(struct pmfs2_inode_info *dir_pii)
{
	return _dir_pi_root(dir_pii->pi);
}

static struct pmfs2_dirents_block *
_dirents_block(struct super_block *sb, ulong bn)
{
	return pmfs2_baddr(sb, bn);
}

static struct pmfs2_dirent *
_lookup_dirent(struct super_block *sb, struct pmfs2_inode_info *dir_pii,
	       const struct qstr *name, ulong *bn)
{
	struct pmfs2_dirent *dirent;
	struct pmfs2_dirents_block *deb;

	*bn = _dir_root(dir_pii);
	deb = _dirents_block(sb, *bn);
	while (deb) {
		dirent = _de_lookup(deb, name->name, name->len);
		if (dirent)
			return dirent;

		*bn = _dir_next(deb);
		deb = _dirents_block(sb, *bn);
	}
	return NULL;
}

struct pmfs2_dirent *
pmfs2_dir_lookup(struct super_block *sb, struct pmfs2_inode_info *dir_pii,
		 const struct qstr *name)
{
	ulong bn;

	return _lookup_dirent(sb, dir_pii, name, &bn);
}

static void _flush_deb_head(struct pmfs2_dirents_block *deb)
{
	pmfs2_flush_buffer(deb, max(16 + PMFS2_DIRENT_SIZE, PMFS2_CL_SIZE));
}

static void _init_dirents_block(struct pmfs2_dirents_block *deb, long base_off)
{
	deb->next = 0;
	deb->base_off = cpu_to_le64(base_off);
	deb->de[0].ino = 0;
	deb->de[0].nde = ARRAY_SIZE(deb->de);
	deb->de[0].nde_prev = 0;
	_flush_deb_head(deb);
}

static int _add_dirents_block(struct super_block *sb, struct inode *dir)
{
	struct pmfs2_inode_info *dir_pii = PMFS2_I(dir);
	struct pmfs2_inode *pi = dir_pii->pi;
	struct pmfs2_dirents_block *deb, *itr;
	ulong bn, next, nblocks = pmfs2_pi_blocks(pi);
	long base_off;
	int err;

	err = pmfs2_new_block(sb, &bn, 1);
	if (unlikely(err))
		return err;

	deb = pmfs2_baddr(sb, bn);
	base_off = 2 + (long)(nblocks * ARRAY_SIZE(deb->de));
	_init_dirents_block(deb, base_off);

	next = _dir_root(dir_pii);
	if (!next) {
		pi->i_btree.root = cpu_to_le64(bn);
		goto out;
	}

	itr = pmfs2_baddr(sb, next);
	while (itr->next) {
		next = le64_to_cpu(itr->next);
		itr = pmfs2_baddr(sb, next);
	}
	itr->next = cpu_to_le64(bn);
	_flush_deb_head(itr);

out:
	pmfs2_pi_blocks_add(pi, 1);
	pmfs2_pi_size_add(pi, PMFS2_BLOCK_SIZE);
	pmfs2_flush_pi(sb, pi);
	return 0;
}

static u8 _file_type_of(struct pmfs2_inode *pi)
{
	uint mode = pmfs2_pi_mode(pi);

	return IFTODT(mode);
}

static ulong _dir_ndents(struct pmfs2_inode *pi)
{
	return le64_to_cpu(pi->i_dir_ndents);
}

static void _dir_inc_ndents(struct pmfs2_inode *pi)
{
	ulong ndents = _dir_ndents(pi);

	pi->i_dir_ndents = cpu_to_le64(ndents + 1);
}

static void _dir_dec_ndents(struct pmfs2_inode *pi)
{
	ulong ndents = _dir_ndents(pi);

	WARN_ON(!ndents);
	pi->i_dir_ndents = cpu_to_le64(ndents - 1);
}


static loff_t _add_dirent(struct super_block *sb, struct inode *dir,
			  const struct qstr *str, struct pmfs2_inode *pi)
{
	struct pmfs2_inode_info *dir_ii = PMFS2_I(dir);
	struct pmfs2_dirents_block *deb;
	ulong bn, ino = pmfs2_pi_ino(pi);
	u8 file_type = _file_type_of(pi);
	loff_t de_off = -1;

	bn = _dir_root(dir_ii);
	deb = _dirents_block(sb, bn);
	while (deb) {
		de_off = _de_add(deb, str, ino, file_type);
		if (de_off > 0) {
			_dir_inc_ndents(dir_ii->pi);
			break;
		}

		bn = _dir_next(deb);
		deb = _dirents_block(sb, bn);
	}
	return de_off;
}

static int _dir_add(struct super_block *sb, struct inode *dir,
		    const struct qstr *name, struct pmfs2_inode *pi)
{
	int err = 0;
	loff_t de_off;

	de_off = _add_dirent(sb, dir, name, pi);
	if (likely(de_off > 0))
		goto out;

	err = _add_dirents_block(sb, dir);
	if (unlikely(err))
		goto out;

	de_off = _add_dirent(sb, dir, name, pi);
	if (unlikely(de_off < 0))
		err = -ENOSPC;
out:
	return err;
}


int pmfs2_dir_add(struct super_block *sb, struct inode *dir,
		  const struct qstr *name, struct pmfs2_inode *pi)
{
	/* TODO: refine dir limits */
	if (_pi_isdir(pi) &&
	    (pmfs2_pi_i_size(PMFS2_I(dir)->pi) > (1U << 20)))
		return -EMLINK;

	return _dir_add(sb, dir, name, pi);
}

static bool _empty_dir(struct pmfs2_inode *pidir)
{
	return (pmfs2_pi_i_size(pidir) == 0);
}

static int _remove_dirent(struct super_block *sb,
			  struct inode *dir, const struct qstr *name)
{
	struct pmfs2_dirent *de;
	struct pmfs2_dirents_block *deb;
	struct pmfs2_inode_info *pii = PMFS2_I(dir);
	struct pmfs2_inode *pi = pii->pi;
	loff_t de_off;
	ulong bn;

	de = _lookup_dirent(sb, pii, name, &bn);
	if (unlikely(!de))
		return -ENOENT;

	deb = _dirents_block(sb, bn);
	if (unlikely(!deb))
		return -EFSCORRUPTED;

	de = _de_remove_merge(de, deb->de + ARRAY_SIZE(deb->de));
	de_off = _de_offset(deb, de);
	WARN_ON(de_off < 2);

	_dir_dec_ndents(pi);
	return 0;
}

static void pmfs2_dir_obliterate(struct super_block *sb, struct inode *inode)
{
	struct pmfs2_inode_info *pii = PMFS2_I(inode);
	struct pmfs2_inode *pi = pii->pi;
	struct pmfs2_dirents_block *deb;
	ulong bn, next_bn;

	bn = _dir_root(pii);
	pi->i_btree.root = 0;
	pi->i_blocks = 0;
	pi->i_size = 0;
	pi->i_dir_ndents = 0;
	pmfs2_flush_pi(sb, pi);

	deb = _dirents_block(sb, bn);
	while (deb) {
		next_bn = _dir_next(deb);
		pmfs2_free_block(sb, bn);
		bn = next_bn;
		deb = _dirents_block(sb, bn);
	}
}

static int _dir_remove(struct super_block *sb, struct inode *dir,
		       const struct qstr *name)
{
	int err;

	err = _remove_dirent(sb, dir, name);
	if (unlikely(err))
		return err;

	if (unlikely(!_dir_ndents(PMFS2_I(dir)->pi)))
		pmfs2_dir_obliterate(sb, dir);

	return 0;
}

int pmfs2_dir_remove(struct super_block *sb, struct inode *dir,
		     const struct qstr *name, struct inode *inode)
{
	struct pmfs2_inode *pi = PMFS2_I(inode)->pi;
	int err;

	if (_pi_isdir(pi)) {
		if (unlikely(!_empty_dir(pi))) {
			pmfs2_dbg_info("[%ld] dir not empty i_size=0x%lx\n",
				       pmfs2_pi_ino(pi), pmfs2_pi_i_size(pi));
			return -ENOTEMPTY;
		}
		pmfs2_dir_obliterate(sb, inode);
	}

	err = _dir_remove(sb, dir, name);
	if (unlikely(err))
		return err;

	return 0;
}

static bool _dir_emit(struct pmfs2_readdir_ctx *ctx,
		      const char *name, size_t name_len, ulong ino, u8 dt)
{
	bool ret;

	WARN_ON(!ino);
	WARN_ON(!name_len);
	ret = zufs_zde_emit(&ctx->rdi, ino, dt,
			    ctx->pos, name, (uint8_t)name_len);
	if (likely(ret))
		ctx->cnt++;

	return ret;
}

static bool _dir_emit_d(struct pmfs2_readdir_ctx *ctx,
			const char *name, ulong ino)
{
	return _dir_emit(ctx, name, strlen(name), ino, IFTODT(S_IFDIR));
}

static bool _dir_emit_de(struct pmfs2_readdir_ctx *ctx,
			 struct pmfs2_dirent *de)
{
	return _dir_emit(ctx, de->name, de->name_len,
			 pmfs2_de_ino(de), de->file_type);
}

static bool _dir_emit_deb(struct pmfs2_readdir_ctx *ctx,
			  struct pmfs2_dirents_block *deb)
{
	struct pmfs2_dirent *itr = deb->de;
	struct pmfs2_dirent *end = itr + ARRAY_SIZE(deb->de);

	/* iterate to first active entry relative to stream's pos */
	while (itr < end) {
		if (_de_active(itr)) {
			loff_t pos = _de_offset(deb, itr);

			if (pos >= ctx->pos) {
				ctx->pos = pos;
				break;
			}
		}
		itr = _de_next(itr);
	}
	/* emit active entries */
	while (itr < end) {
		if (_de_active(itr)) {
			if (!_dir_emit_de(ctx, itr))
				return false;
		}
		itr = _de_next(itr);
		ctx->pos = _de_offset(deb, itr);
	}
	return true;

}

static ulong _dir_parent_ino(struct pmfs2_inode *pi)
{
	return (pmfs2_pi_ino(pi) == PMFS2_ROOT_INO) ?
	       PMFS2_ROOT_INO : le64_to_cpu(pi->i_dir_parent);
}

int pmfs2_dir_readdir(struct super_block *sb, struct inode *inode,
		      struct pmfs2_readdir_ctx *ctx)
{
	struct pmfs2_inode_info *dir_pii = PMFS2_I(inode);
	struct pmfs2_dirents_block *deb;
	ulong i_size;
	bool ret;

	pmfs2_dbg_vfs("[%ld] pos=0x%lx\n", pmfs2_pi_ino(dir_pii->pi), ctx->pos);

	if (ctx->pos == 0) {
		ret = _dir_emit_d(ctx, ".", pmfs2_pi_ino(dir_pii->pi));
		if (unlikely(!ret))
			return 0;
		ctx->pos = 1;
	}
	if (ctx->pos == 1) {
		ret = _dir_emit_d(ctx, "..", _dir_parent_ino(dir_pii->pi));
		if (unlikely(!ret))
			return 0;
		ctx->pos = 2;
	}
	i_size = pmfs2_pi_i_size(dir_pii->pi);
	if ((i_size + 2) <= (ulong)ctx->pos)
		return 0;

	deb = _dirents_block(sb, _dir_root(dir_pii));
	while (deb) {
		if (!_dir_emit_deb(ctx, deb))
			break;
		deb = _dirents_block(sb, _dir_next(deb));
	}
	return 0;
}

int pmfs2_dir_rename(struct super_block *sb, struct inode *old_dir,
		     struct inode *old_inode, struct qstr *old_name,
		     struct inode *new_dir, struct inode *new_inode,
		     struct qstr *new_name, uint flags)
{
	struct pmfs2_inode *old_pi = pmfs2_pi(old_inode);
	struct pmfs2_inode *new_pi = new_inode ? pmfs2_pi(new_inode) : NULL;
	struct pmfs2_dirent *new_de;
	struct pmfs2_dirent *old_de;
	int err;

	if (!(flags & RENAME_EXCHANGE) && _pi_isdir(old_pi)) {
		if (new_pi && !_empty_dir(new_pi))
			return -ENOTEMPTY;
	}

	if (flags)  /* RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT */
		return -ENOTSUP;

	/*
	 * TODO: FIXME
	 * Just a code to "make it work"
	 */
	old_de = pmfs2_dir_lookup(sb, PMFS2_I(old_dir), old_name);
	if (unlikely(!old_de))
		return -ENOENT;

	err = _dir_remove(sb, old_dir, old_name);
	if (unlikely(err))
		return err;

	new_de = pmfs2_dir_lookup(sb, PMFS2_I(new_dir), new_name);
	if (new_de) {
		err = _dir_remove(sb, new_dir, new_name);
		if (unlikely(err))
			return err;
	}
	err = _dir_add(sb, new_dir, new_name, old_pi);
	if (unlikely(err))
		return err;

	if (_pi_isdir(old_pi)) {
		pmfs2_pi_nlink_dec(pmfs2_pi(old_dir));
		pmfs2_pi_nlink_add(pmfs2_pi(new_dir));
	}

	pmfs2_flush_pi(sb, old_pi);
	if ((new_inode != old_inode) && new_inode)
		pmfs2_flush_pi(sb, new_pi);
	pmfs2_flush_pi(sb, pmfs2_pi(old_dir));
	if (new_dir != old_dir)
		pmfs2_flush_pi(sb, pmfs2_pi(new_dir));

	return err;
}

int pmfs2_dir_recon(struct super_block *sb, struct pmfs2_inode *dir_pi)
{
	struct pmfs2_dirents_block *deb;
	ulong bn;
	int err;

	bn = _dir_pi_root(dir_pi);
	deb = _dirents_block(sb, bn);
	while (deb) {
		err = pmfs2_mark_bn_active(sb, bn);
		if (unlikely(err))
			return err;

		bn = _dir_next(deb);
		/* TODO: check bn within valid-range */
		deb = _dirents_block(sb, bn);
	}
	return 0;
}
