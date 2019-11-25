// SPDX-License-Identifier: GPL-2.0
/* See module.c for license details. */

#define _GNU_SOURCE 1
#include <sys/uio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <limits.h>
#include <sched.h>
#include "pmfs2.h"

#define QSTR_INIT(str) { .len = (str)->len, .name = (str)->name }


/* locals */
static const struct zus_zfi_operations pmus_zfi_operations;
static const struct zus_sbi_operations pmus_sbi_operations;
static const struct zus_zii_operations	pmus_zii_operations;


static int _parse_options(struct pmfs2_sb_info *sbi,
			  struct zufs_parse_options *po, bool remount)
{
	if (po->mount_options_len > 1) {
		pmfs2_warn("unsupported mount options '%s'\n",
			   po->mount_options);
		return -EINVAL;
	}
	if (remount) {
		pmfs2_warn("unsupported remount=%d\n", (int)remount);
		return -EINVAL;
	}
	sbi->s_mount_flags = po->mount_flags;
	return 0;
}

static int pmus_show_options(struct zus_sb_info *zsbi,
			     struct zufs_ioc_mount_options *zim)
{
	struct pmfs2_sb_info *sbi = PSBI(zsbi);
	char *buf = zim->buf;
	ssize_t size = 0;

	buf[0] = 0;
	zim->hdr.out_len = size;
	(void)sbi;

	return 0;
}

static struct zus_sb_info *pmus_sbi_alloc(struct zus_fs_info *zfi)
{
	struct pmfs2_sb_info *sbi;

	sbi = pmfs2_zalloc(sizeof(*sbi));
	if (unlikely(!sbi))
		return NULL;

	pmfs2_dbg_vfs("sbi=%p\n", sbi);
	sbi->zsbi.op = &pmus_sbi_operations;
	sbi->md = &sbi->zsbi.md;
	sbi->sb = &sbi->_sb;
	sbi->sb->s_fs_info = sbi;

	return &sbi->zsbi;
}

static void pmus_sbi_free(struct zus_sb_info *zsbi)
{
	struct pmfs2_sb_info *sbi = PSBI(zsbi);

	pmfs2_dbg_vfs("sbi=%p\n", sbi);
	pmfs2_free(sbi);
}

static struct zus_inode_info *_zii_alloc(struct zus_sb_info *zsbi)
{
	struct pmfs2_inode_info *pii;

	pii = pmfs2_zalloc(sizeof(*pii));
	if (unlikely(!pii))
		return NULL;

	pii->zii.op = &pmus_zii_operations;
	pii->zii.sbi = zsbi;

	pmfs2_pii_init_once(pii, PSBI(zsbi));

	return &pii->zii;
}

static inline void _zii_free(struct zus_inode_info *zii)
{
	struct pmfs2_inode_info *pii = ZPII(zii);

	pmfs2_free(pii);
}

static void pmus_set_pii(struct zus_inode_info *zii, struct pmfs2_inode *pi)
{
	struct pmfs2_inode_info *pii = ZPII(zii);

	zii->zi = PZI(pi);
	pmfs2_pi_set_pii(&pii->vfs_inode, pi);
}

static struct zus_inode_info *_root_zii_init(struct zus_sb_info *zsbi)
{
	struct pmfs2_sb_info *sbi = PSBI(zsbi);
	struct pmfs2_inode *pi;
	struct zus_inode_info *zii;

	if (unlikely(zsbi->z_root)) {
		pmfs2_warn("sbi->z_root=%p\n", zsbi->z_root);
		return ERR_PTR(-EINVAL);
	}

	pi = pmfs2_pi_find_by_ino(sbi->sb, PMFS2_ROOT_INO);
	if (unlikely(!pi))
		return ERR_PTR(-EINVAL);

	zii = _zii_alloc(zsbi);
	if (unlikely(!zii))
		return ERR_PTR(-ENOMEM);

	pmus_set_pii(zii, pi);
	return zii;
}

static inline void _root_zii_fini(struct zus_sb_info *sbi)
{
	if (sbi->z_root) {
		pmfs2_free(ZPII(sbi->z_root));
		sbi->z_root = NULL;
	}
}

/*
 * Require no more then single device which is associated with active CPU
 */
static int _verify_pmem(struct zus_sb_info *zsbi)
{
	cpu_set_t cpuset;
	struct multi_devices *md = &zsbi->md;
	struct md_dev_info *mdi;
	struct zufs_ioc_numa_map *numa_map = zus_numa_map;

	if (md->t1_count != 1) {
		pmfs2_warn("unsupported t1_count=%d\n", md->t1_count);
		return -EINVAL;
	}

	mdi = md_t1_dev(md, 0);
	if ((mdi->nid < 0) || (mdi->nid >= (int)numa_map->possible_nodes)) {
		pmfs2_warn("illegal nodeid=%d\n", mdi->nid);
		return -EINVAL;
	}

	memcpy(&cpuset, &numa_map->cpu_set_per_node[mdi->nid], sizeof(cpuset));
	if (!CPU_COUNT(&cpuset)) {
		pmfs2_warn("no active CPU on nodeid=%d\n", mdi->nid);
		return -EINVAL;
	}
	return 0;
}

static int pmus_sbi_init(struct zus_sb_info *zsbi, struct zufs_mount_info *zmi)
{
	struct pmfs2_inode *root_pi;
	ulong root_ino;
	int err;

	pmfs2_dbg_vfs("sbi=%p sb_id=%lld\n", zsbi, zsbi->kern_sb_id);

	err = _verify_pmem(zsbi);
	if (unlikely(err))
		return err;

	err = pmfs2_sbi_init(ZSB(zsbi), PSBI(zsbi), &zsbi->md);
	if (unlikely(err))
		return err;

	err = _parse_options(PSBI(zsbi), &zmi->po, false);
	if (unlikely(err))
		return err;

	zsbi->z_root = _root_zii_init(zsbi);
	if (IS_ERR(zsbi->z_root)) {
		pmfs2_warn("_root_zii_init failed err=%ld\n",
			   PTR_ERR(zsbi->z_root));
		return PTR_ERR(zsbi->z_root);
	}

	err = pmfs2_sbi_recon(ZSB(zsbi), ZVI(zsbi->z_root));
	if (unlikely(err)) {
		pmfs2_warn("pmfs2_sbi_recon failed => %d\n", err);
		return err;
	}

	root_ino = PMFS2_ROOT_INO;
	root_pi = pmfs2_pi_find_by_ino(ZSB(zsbi), root_ino);
	if (unlikely(!root_pi)) {
		pmfs2_warn("failed to find-by-ino ino=%lu\n", root_ino);
		return -EINVAL;
	}

	zsbi->z_root->zi = PZI(root_pi);
	zmi->s_blocksize_bits = PMFS2_BLOCK_SHIFT;
	zmi->fs_caps = ZUFS_FSC_NIO_READS;
	zmi->fs_caps |= ZUFS_FSC_NIO_WRITES;
	return 0;
}

static int pmus_sbi_fini(struct zus_sb_info *zsbi)
{
	pmfs2_dbg_vfs("sbi=%p\n", zsbi);

	pmfs2_sbi_fini(ZSB(zsbi));
	_root_zii_fini(zsbi);

	return 0;
}

/* zus_sbi_operations */

static inline void _set_pi_from_zi(struct pmfs2_inode *pi, struct zus_inode *zi)
{
	__u16 mode = le16_to_cpu(zi->i_mode);

	pi->i_mode = zi->i_mode;
	pi->i_uid = zi->i_uid;
	pi->i_gid = zi->i_gid;
	pi->i_nlink = zi->i_nlink;
	pi->i_atime = zi->i_atime;
	pi->i_mtime = zi->i_mtime;
	pi->i_ctime = zi->i_ctime;
	pi->i_generation = zi->i_generation;
	pi->i_flags = zi->i_flags;

	if (S_ISCHR(mode) || S_ISBLK(mode))
		pi->i_rdev = zi->i_rdev;
}

static struct zus_inode_info *
pmus_new_inode(struct zus_sb_info *zsbi, void *app_ptr,
	       struct zufs_ioc_new_inode *zni)
{
	struct zus_inode *zi = &zni->zi;
	struct zus_inode_info *dir_zii = zni->dir_ii;
	struct pmfs2_inode *pi;
	char *symname = NULL;
	struct zus_inode_info *zii = NULL;

	zii = _zii_alloc(zsbi);
	if (unlikely(!zii))
		return NULL;

	if (zi_islnk(zi))
		symname = (zi->i_size >= sizeof(zi->i_symlink)) ?
			  app_ptr : (char *)zi->i_symlink;

	pi = pmfs2_pi_new(ZSB(zsbi), zi_isdir(zi),
			  zi_ino(dir_zii->zi), symname);
	if (IS_ERR(pi)) {
		_zii_free(zii);
		zii = NULL;
		goto out;
	}

	_set_pi_from_zi(pi, zi);
	pmus_set_pii(zii, pi);
	if (zi_isdir(PZI(pi)))
		zus_std_new_dir(zni->dir_ii->zi, PZI(pi));

	pmfs2_flush_pi(ZSB(zsbi), pi);

	pmfs2_dbg_vfs("[%ld] parent=0x%lx\n",
		      zi_ino(zii->zi), zi_ino(dir_zii->zi));
out:
	return zii;
}

static void pmus_free_inode(struct zus_inode_info *zii)
{
	struct pmfs2_inode_info *pii = ZPII(zii);
	struct pmfs2_inode *pi = pii->pi;
	struct super_block *sb = ZSB(zii->sbi);

	if (unlikely(!pi))
		return;

	pmfs2_pi_lock(sb, pi);

	/* TODO: ref count per pi */
	if (!pi->i_nlink)
		pmfs2_pi_free(sb, ZVI(zii));

	pmfs2_pi_unlock(sb, pi);

	_zii_free(zii);
}

static ulong pmus_lookup(struct zus_inode_info *zii, struct zufs_str *str)
{
	struct pmfs2_dirent *de;
	struct pmfs2_inode_info *dir_pii = ZPII(zii);
	struct super_block *sb = ZSB(zii->sbi);
	struct qstr name = QSTR_INIT(str);

	pmfs2_dbg_vfs("parent=0x%lx str=%.*s\n",
		      zi_ino(zii->zi), str->len, str->name);

	de = pmfs2_dir_lookup(sb, dir_pii, &name);
	if (unlikely(!de))
		return 0;

	return pmfs2_de_ino(de);
}

static int pmus_add_dentry(struct zus_inode_info *dir_ii,
			   struct zus_inode_info *zii, struct zufs_str *str)
{
	struct super_block *sb = ZSB(dir_ii->sbi);
	struct qstr qstr = QSTR_INIT(str);
	struct pmfs2_inode *pidir = ZPII(dir_ii)->pi;
	int err;

	pmfs2_dbg_vfs("ino=0x%lx parent=0x%lx name=%.*s\n",
		      zi_ino(zii->zi), zi_ino(dir_ii->zi), str->len, str->name);

	zus_std_add_dentry(dir_ii->zi, zii->zi);
	pmfs2_flush_pi(sb, ZPII(zii)->pi);

	err = pmfs2_dir_add(sb, ZVI(dir_ii), &qstr, ZPII(zii)->pi);
	if (unlikely(err)) {
		zus_std_remove_dentry(dir_ii->zi, zii->zi);
		pmfs2_flush_pi(sb, pidir);
		pmfs2_flush_pi(sb, ZPII(zii)->pi);
	}
	return err;
}

static int pmus_remove_dentry(struct zus_inode_info *dir_ii,
			      struct zus_inode_info *zii,
			      struct zufs_str *str)
{
	struct super_block *sb = ZSB(dir_ii->sbi);
	struct pmfs2_inode *pidir = ZPII(dir_ii)->pi;
	struct pmfs2_inode *pi = ZPII(zii)->pi;
	struct qstr qstr = QSTR_INIT(str);
	int err;

	pmfs2_dbg_vfs("ino=0x%lx parent=0x%lx name=%.*s\n",
		      zi_ino(zii->zi), zi_ino(dir_ii->zi), str->len, str->name);

	err = pmfs2_dir_remove(sb, ZVI(dir_ii), &qstr, ZVI(zii));
	if (unlikely(err))
		return err;

	zus_std_remove_dentry(dir_ii->zi, zii->zi);

	pmfs2_flush_pi(sb, pidir);
	pmfs2_flush_pi(sb, pi);
	return 0;
}

static int _pmus_iget_pi(struct zus_sb_info *zsbi, struct pmfs2_inode *pi,
			 struct zus_inode_info **zii)
{
	int err = 0;

	if (pmfs2_pi_ino(pi) == PMFS2_ROOT_INO) {
		*zii = zsbi->z_root;
		return 0;
	}

	*zii = _zii_alloc(zsbi);
	if (unlikely(!*zii)) {
		err = -ENOMEM;
		goto out;
	}
	pmus_set_pii(*zii, pi);

out:
	return err;
}

static int pmus_iget(struct zus_sb_info *zsbi, ulong ino,
		     struct zus_inode_info **zii)
{
	struct pmfs2_inode *pi;

	pmfs2_dbg_vfs("ino=0x%lx\n", ino);

	pi = pmfs2_pi_find_by_ino(ZSB(zsbi), ino);
	if (!pi || !pmfs2_pi_active(pi))
		return -ENOENT;

	return _pmus_iget_pi(zsbi, pi, zii);
}

static int pmus_rename(struct zufs_ioc_rename *zir)
{
	struct super_block *sb = ZSB(zir->old_dir_ii->sbi);
	struct qstr old_name = QSTR_INIT(&zir->old_d_str);
	struct qstr new_name = QSTR_INIT(&zir->new_d_str);
	int err;

	if (unlikely(!zir->old_zus_ii))
		return -EINVAL;

	/*
	 * TODO: Support flags:
	 *   RENAME_NOREPLACE | RENAME_EXCHANGE | RENAME_WHITEOUT
	 */
	if (zir->flags)
		return -ENOTSUP;

	err = pmfs2_dir_rename(sb, ZVI(zir->old_dir_ii),
			       ZVI(zir->old_zus_ii),
			       &old_name,
			       ZVI(zir->new_dir_ii),
			       zir->new_zus_ii ? ZVI(zir->new_zus_ii) : NULL,
			       &new_name, zir->flags);
	return err;
}

static int pmus_readdir(void *app_ptr, struct zufs_ioc_readdir *zir)
{
	int err;
	struct pmfs2_readdir_ctx ctx = {
		.pos = zir->pos,
	};

	zufs_readdir_iter_init(&ctx.rdi, zir, app_ptr);
	err = pmfs2_dir_readdir(ZSB(zir->dir_ii->sbi), ZVI(zir->dir_ii), &ctx);
	zir->pos = ctx.pos;

	return err;
}

static int pmus_statfs(struct zus_sb_info *sbi,
		       struct zufs_ioc_statfs *ioc_statfs)
{
	memset(&ioc_statfs->statfs_out, 0, sizeof(struct statfs64));
	return pmfs2_sbi_statfs(ZSB(sbi), &ioc_statfs->statfs_out);
}

/* struct zus_zii_operations  */

static void _pmus_IO_ziom_init(struct zufs_ioc_IO *io, struct iov_iter *iter)
{
	_zus_iom_init_4_ioc_io(&iter->iomb, NULL, io, ZUS_MAX_OP_SIZE);
}

static int _pmus_IO_finalize(struct zufs_ioc_IO *io, struct iov_iter *iter)
{
	_zus_iom_end(&iter->iomb);
	io->ziom.iom_n = _zus_iom_len(&iter->iomb);
	io->hdr.out_len = sizeof(*io);
	if (io->ziom.iom_n > ZUFS_WRITE_OP_SPACE)
		io->hdr.out_len +=
			(io->ziom.iom_n - ZUFS_WRITE_OP_SPACE) *
			sizeof(__u64);
	io->ziom.iomb = pmfs2_zalloc(sizeof(iter->iomb));
	if (!io->ziom.iomb) {
		iter->iomb.err = -ENOMEM;
		if (iter->iomb.done)
			iter->iomb.done(&iter->iomb);

		return -ENOMEM;
	}
	*io->ziom.iomb = iter->iomb;
	return -EZUFS_RETRY;
}

static void _pmus_IO_done(struct zufs_ioc_IO *io)
{
	if (io->ziom.iomb->done) {
		io->ziom.iomb->err = io->hdr.err;
		io->ziom.iomb->done(io->ziom.iomb);
	}
	pmfs2_free(io->ziom.iomb);
	io->ziom.iomb = NULL;
}

static int _read(void *app_ptr, struct zufs_ioc_IO *io, struct kiocb *kiocb)
{
	struct iov_iter iter = {};
	struct iovec iov = {};
	ssize_t ret;

	iov_iter_init_single(&iter, app_ptr, io->hdr.len, &iov);

	_pmus_IO_ziom_init(io, &iter);

	ret = pmfs2_rw_read_iter(ZSB(io->zus_ii->sbi), ZVI(io->zus_ii),
				 kiocb, &iter);

	if (unlikely(ret == -EZUFS_RETRY))
		return _pmus_IO_finalize(io, &iter);

	if (unlikely(ret < 0))
		return ret;

	io->last_pos = io->filepos + ret;
	return 0;
}

static int pmus_read(void *app_ptr, struct zufs_ioc_IO *io)
{
	struct kiocb kiocb = {
		.ki_pos = io->filepos,
		.ki_flags = io->rw,
		.ra = &io->ra,
	};

	if (io->ziom.iomb)
		_pmus_IO_done(io);

	return _read(app_ptr, io, &kiocb);
}

static int pmus_pre_read(void *app_ptr, struct zufs_ioc_IO *io)
{
	struct kiocb kiocb = {
		.ki_pos = io->filepos,
		.ki_flags = IOCB_PRE_READ,
		.ra = &io->ra,
	};

	if (io->ziom.iomb)
		_pmus_IO_done(io);

	if (!io->ra.ra_pages)
		return 0;

	return _read(app_ptr, io, &kiocb);
}

static int pmus_write(void *app_ptr, struct zufs_ioc_IO *io)
{
	struct kiocb kiocb = {
		.ki_pos = io->filepos,
	};
	struct iov_iter ii = {};
	struct iovec iov = {};
	ssize_t ret;

	kiocb.ki_flags = io->rw;

	if (io->ziom.iomb)
		_pmus_IO_done(io);

	ii.unmap = &io->wr_unmap;
	iov_iter_init_single(&ii, app_ptr, io->hdr.len, &iov);

	_pmus_IO_ziom_init(io, &ii);

	ret = pmfs2_rw_write_iter(ZSB(io->zus_ii->sbi), ZVI(io->zus_ii),
				  &kiocb, &ii);

	if (unlikely(ret == -EZUFS_RETRY))
		return _pmus_IO_finalize(io, &ii);

	if (unlikely(ret < 0))
		return ret;

	io->last_pos = io->filepos + ret;
	return 0;
}

static int pmus_get_block(struct zus_inode_info *zii,
			  struct zufs_ioc_IO *get_block)
{
	int ret, err;
	struct iov_iter ii = {};
	struct pmfs2_gbi gbi = {};
	struct pmfs2_inode *pi = PMFS2_I(ZVI(zii))->pi;
	ulong index = pmfs2_o2b(get_block->filepos);
	struct super_block *sb = ZSB(zii->sbi);
	bool retry_return = false;

	if (get_block->ziom.iomb) {
		retry_return = true;
		_pmus_IO_done(get_block);
	}

	gbi.iomb = &ii.iomb;
	_pmus_IO_ziom_init(get_block, &ii);

	if (get_block->rw & WRITE) {
		struct pmfs2_gbi gbi_read = {};

		err = 0;
		if (!retry_return) {
			gbi_read.iomb = gbi.iomb;
			err = pmfs2_get_data_block(sb, pi,
						   index, READ, &gbi_read);
			if (unlikely(err))
				return err;
		}

		ret = pmfs2_get_block_create(sb, pi, index, WRITE, &gbi);
		pmfs2_flush_pi(sb, pi);

		if (unlikely(ret < 0)) {
			err = ret;
			goto out;
		}

		if (!retry_return)
			pmfs2_put_data_block(sb, &gbi_read);

		WARN_ON(!gbi.bn);
		get_block->ret_flags = (ret == 1) ? ZUFS_RET_NEW : 0;
	} else
		err = pmfs2_get_data_block(sb, pi, index, READ, &gbi);
out:
	get_block->cookie = gbi.rw;
	if (unlikely(err)) {
		if (err == -EZUFS_RETRY)
			err = _pmus_IO_finalize(get_block, &ii);
		return err;
	}

	_zus_iom_start(gbi.iomb, NULL, NULL);
	_ziom_enc_t1_bn(gbi.iomb, gbi.bn, 0);
	get_block->hdr.out_len = _ioc_IO_size(1);

	return err;
}

static int pmus_put_block(struct zus_inode_info *zii,
			  struct zufs_ioc_IO *get_block)
{
	struct pmfs2_gbi gbi = {};

	gbi.rw = get_block->cookie;
	gbi.bn = _zufs_iom_t1_bn(get_block->iom_e[0]);

	if (unlikely(gbi.bn == ((ulong) -1)))
		pmfs2_err("gbi.bn=0x%lx rw=0x%x val=0x%llx\n",
			 gbi.bn, gbi.rw, get_block->iom_e[0]);
	else if (likely(gbi.bn))
		pmfs2_put_data_block(ZSB(zii->sbi), &gbi);

	return 0;
}

static int _get_multy(struct zus_inode_info *zii, struct zufs_ioc_IO *io)
{
	struct kiocb kiocb = {
		.ki_pos = io->filepos,
		.ki_flags = io->rw,
		.ra = &io->ra,
	};
	struct iov_iter ii = {};
	struct iovec iov = {};
	ssize_t ret;

	if (io->rw & ZUFS_RW_MMAP)
		return pmus_get_block(zii, io);

	if (io->ziom.iomb)
		_pmus_IO_done(io);

	iov_iter_init_single(&ii, NULL, io->hdr.len, &iov);
	_pmus_IO_ziom_init(io, &ii);

	if (io->rw & WRITE) {
		ii.unmap = &io->wr_unmap;
		ret = pmfs2_rw_get_multy_write(ZSB(io->zus_ii->sbi),
					      ZVI(io->zus_ii), &kiocb, &ii);
	} else {
		ret = pmfs2_rw_get_multy_read(ZSB(io->zus_ii->sbi),
					     ZVI(io->zus_ii), &kiocb, &ii);
	}
	if (unlikely(ret == -EZUFS_RETRY))
		return _pmus_IO_finalize(io, &ii);

	if (unlikely(ret < 0))
		return ret;

	io->hdr.out_len = _ioc_IO_size(io->ziom.iom_n);
	io->ret_flags = kiocb.ret_flags;
	io->last_pos = io->filepos + ret;

	return 0;
}

static int _put_multy(struct zus_inode_info *zii,
		      struct zufs_ioc_IO *io)
{
	if (io->rw & ZUFS_RW_MMAP)
		return pmus_put_block(zii, io);

	pmfs2_rw_put_multy(ZSB(zii->sbi), ZVI(io->zus_ii), io);
	return 0;
}

static int pmus_get_put_multy(struct zus_inode_info *zii,
			      struct zufs_ioc_IO *io)
{
	if (io->hdr.operation == ZUFS_OP_GET_MULTY)
		return _get_multy(zii, io);
	else
		return _put_multy(zii, io);
}

static int pmus_mmap_close(struct zus_inode_info *zii,
			   struct zufs_ioc_mmap_close *mmap_close)
{
	pmfs2_dbg_vfs("[%ld] mmap_close",
		      pmfs2_pi_ino(pmfs2_pi(ZVI(mmap_close->zus_ii))));
	return 0;
}

static int pmus_setattr(struct zus_inode_info *zii, uint enable_bits)
{
	struct super_block *sb = ZSB(zii->sbi);

	if (enable_bits & STATX_SIZE)
		pmfs2_err("setattr with enable_bits=0x%x\n", enable_bits);

	if (enable_bits & ~(STATX_MODE | STATX_UID | STATX_GID | STATX_SIZE |
			    STATX_ATIME | STATX_CTIME | STATX_MTIME |
			    ZUFS_STATX_FLAGS | ZUFS_STATX_VERSION)) {
		pmfs2_warn("unknown setattr enable_bits=0x%x\n", enable_bits);
		return 0;
	}

	return pmfs2_pi_setattr(sb, ZVI(zii));
}

static int pmus_sync(struct zus_inode_info *zii,
		     struct zufs_ioc_sync *ioc_range)
{
	struct super_block *sb = ZSB(zii->sbi);
	int err;

	if (ioc_range->flags & ZUFS_SF_DONTNEED)
		return 0;

	err = pmfs2_pi_sync(sb, ZVI(zii),
			    ioc_range->offset,
			    ioc_range->offset + ioc_range->length,
			    ioc_range->flags);
	ioc_range->write_unmapped = 0;
	return err;
}

static int pmus_fallocate(struct zus_inode_info *zii,
			  struct zufs_ioc_IO *io)
{
	struct iov_iter ii = {};
	int err;

	if (io->ziom.iomb)
		_pmus_IO_done(io);

	_pmus_IO_ziom_init(io, &ii);

	err = pmfs2_rw_fallocate(ZSB(zii->sbi), ZVI(zii), (int)io->rw,
				 (loff_t)io->filepos,
				 (loff_t)io->last_pos, &ii);

	if (unlikely(err == -EZUFS_RETRY))
		err = _pmus_IO_finalize(io, &ii);

	return err;
}

static int pmus_seek(struct zus_inode_info *zii, struct zufs_ioc_seek *ioc_seek)
{
	loff_t off;

	off = pmfs2_pi_lseek_data_hole(ZSB(zii->sbi), ZVI(zii),
				       (loff_t)ioc_seek->offset_in,
				       (int)ioc_seek->whence);
	if (unlikely(off < 0))
		return (int)off;

	ioc_seek->offset_out = (uint64_t)off;
	return 0;
}

static int pmus_getxattr(struct zus_inode_info *zii,
			 struct zufs_ioc_xattr *ioc_xattr)
{
	ssize_t size;

	size = pmfs2_getxattr(ZSB(zii->sbi), ZVI(zii), ioc_xattr->type,
			     ioc_xattr->buf, ioc_xattr->buf,
			     ioc_xattr->user_buf_size);
	if (unlikely(size < 0))
		return size;

	if (ioc_xattr->user_buf_size)
		ioc_xattr->hdr.out_len += size;
	ioc_xattr->user_buf_size = size;
	return 0;
}

static int pmus_setxattr(struct zus_inode_info *zii,
			 struct zufs_ioc_xattr *ioc_xattr)
{
	void *value = NULL;
	int err;

	if (ioc_xattr->user_buf_size ||
	    (ioc_xattr->ioc_flags & ZUFS_XATTR_SET_EMPTY))
		value = ioc_xattr->buf + ioc_xattr->name_len;

	err = pmfs2_setxattr(ZSB(zii->sbi), ZVI(zii), ioc_xattr->type,
			     ioc_xattr->buf, value, ioc_xattr->user_buf_size,
			     ioc_xattr->flags & ~ZUFS_XATTR_SET_EMPTY);
	return err;
}

static int pmus_listxattr(struct zus_inode_info *zii,
			  struct zufs_ioc_xattr *ioc_xattr)
{
	ssize_t size;

	size = pmfs2_listxattr(ZSB(zii->sbi), ZVI(zii), ioc_xattr->buf,
			       ioc_xattr->user_buf_size,
			       ioc_xattr->ioc_flags & ZUFS_XATTR_TRUSTED);
	if (unlikely(size < 0))
		return size;

	if (ioc_xattr->user_buf_size)
		ioc_xattr->hdr.out_len += size;
	ioc_xattr->user_buf_size = size;
	return 0;
}

static const struct zus_zfi_operations pmus_zfi_operations = {
	.sbi_alloc      = pmus_sbi_alloc,
	.sbi_free       = pmus_sbi_free,
	.sbi_init       = pmus_sbi_init,
	.sbi_fini       = pmus_sbi_fini,
};

static const struct zus_sbi_operations pmus_sbi_operations = {
	.new_inode      = pmus_new_inode,
	.free_inode     = pmus_free_inode,
	.lookup         = pmus_lookup,
	.iget           = pmus_iget,
	.add_dentry     = pmus_add_dentry,
	.remove_dentry  = pmus_remove_dentry,
	.rename         = pmus_rename,
	.readdir        = pmus_readdir,
	.statfs         = pmus_statfs,
	.show_options   = pmus_show_options,
};

static const struct zus_zii_operations	pmus_zii_operations = {
	.read           = pmus_read,
	.pre_read       = pmus_pre_read,
	.write          = pmus_write,
	.get_put_multy  = pmus_get_put_multy,
	.mmap_close     = pmus_mmap_close,
	.setattr        = pmus_setattr,
	.fallocate      = pmus_fallocate,
	.sync           = pmus_sync,
	.seek           = pmus_seek,
	.getxattr       = pmus_getxattr,
	.setxattr       = pmus_setxattr,
	.listxattr      = pmus_listxattr,
};


/* TODO: Make proper define based on btree */
#define	_MAX_SIZE (ULONG_MAX / 2)

static struct zus_fs_info pmfs2_zfi = {
	.rfi.fsname = "pmfs2",
	.rfi.FS_magic = PMFS2_SUPER_MAGIC,
	.rfi.FS_ver_major = PMFS2_MAJOR_VERSION,
	.rfi.FS_ver_minor = PMFS2_MINOR_VERSION,
	.rfi.dt_offset = 0,
	.rfi.s_time_gran = 1,
	.rfi.def_mode = 0755,
	.rfi.s_maxbytes = _MAX_SIZE,
	.op = &pmus_zfi_operations,
	.sbi_op = &pmus_sbi_operations,
	.user_page_size = sizeof(struct page),
	.next_sb_id = 0,
};

int REGISTER_FS_FN(int fd)
{
	return zus_register_one(fd, &pmfs2_zfi);
}
