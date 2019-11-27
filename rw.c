// SPDX-License-Identifier: GPL-2.0
/* See module.c for license details. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <limits.h>
#include "pmfs2.h"
#include "pmfs2_kinu.h"

#define kiocb_ra(kiocb) (kiocb->ra)

ssize_t pmfs2_rw_read_iter(struct super_block *sb, struct inode *inode,
			  struct kiocb *kiocb, struct iov_iter *ii)
{
	struct pmfs2_inode *pi = PMFS2_I(inode)->pi;
	struct file_ra_state *ra = kiocb_ra(kiocb);
	loff_t start = kiocb->ki_pos;
	loff_t pos = start;
	ulong index = pmfs2_o2b(pos);
	unsigned int offset = pos & (PMFS2_BLOCK_SIZE - 1);
	int err = 0;
	int rw = READ;

	if (unlikely(pos > (long)le64_to_cpu(pi->i_size)))
		return 0;

	iov_iter_truncate(ii, le64_to_cpu(pi->i_size) - pos);
	if (unlikely(!iov_iter_count(ii) && !ra->ra_pages))
		return 0;

	if (kiocb->ki_flags & IOCB_PRE_READ)
		index = ra->start;

	while (iov_iter_count(ii)) {
		struct pmfs2_gbi gbi = { .iomb = &ii->iomb };
		unsigned int len, retl;

		len = min_t(unsigned int, PMFS2_BLOCK_SIZE - offset,
			    iov_iter_count(ii));

		err = pmfs2_get_data_block(sb, pi, index, rw, &gbi);
		if (unlikely(err && (err != -ENOENT)))
			return err;

		if (!gbi.bn)
			retl = iov_iter_zero(len, ii);
		else
			retl = copy_to_iter(pmfs2_baddr(sb, gbi.bn) + offset,
					    len, ii);

		pmfs2_put_data_block(sb, &gbi);

		if (unlikely(retl != len))
			return -EFAULT;

		pos += len;
		++index;
		offset = 0;
		err = 0;
	}

	if (start < (long)ra->prev_pos)
		ra->start = pmfs2_o2b(start);

	ra->prev_pos = pos - 1;
	kiocb->ki_pos = pos;

	return unlikely(pos == start) ? err : pos - start;
}

static void _unmap_maping(struct inode *inode, ulong index, ulong num_blocks,
			  struct iov_iter *ii)
{
	if (!ii->unmap->len) {
		ii->unmap->offset = pmfs2_b2o(index);
		ii->unmap->len = pmfs2_b2o(num_blocks);
	} else {
		ulong offset = pmfs2_b2o(index);
		ulong old_end = ii->unmap->offset + ii->unmap->len;
		ulong new_end = offset + pmfs2_b2o(num_blocks);

		if (offset < ii->unmap->offset)
			ii->unmap->offset = offset;
		ii->unmap->len = max(old_end, new_end) - ii->unmap->offset;
	}
}

static size_t
_copy_from_iter_nt(struct super_block *sb, struct pmfs2_gbi *gbi,
		   ulong offset, size_t bytes, struct iov_iter *ii)
{
	void *addr = pmfs2_baddr(sb, gbi->bn) + offset;

	return copy_from_iter_nocache(addr, bytes, ii);
}

ssize_t pmfs2_rw_write_iter(struct super_block *sb, struct inode *inode,
			   struct kiocb *kiocb, struct iov_iter *ii)
{
	struct pmfs2_inode *pi = pmfs2_pi(inode);
	loff_t start = kiocb->ki_pos;
	loff_t pos = start;
	ulong index = pmfs2_o2b(pos);
	unsigned int offset = pos & (PMFS2_BLOCK_SIZE - 1);
	int err = 0;

	while (iov_iter_count(ii)) {
		struct pmfs2_gbi gbi = { .iomb = &ii->iomb };
		unsigned int len, retl;
		int rw = WRITE;

		len = min_t(unsigned int, PMFS2_BLOCK_SIZE - offset,
			    iov_iter_count(ii));

		err = pmfs2_get_data_block(sb, pi, index, rw, &gbi);
		if (err) {
			ulong nblocks;

			if (unlikely(err != -ENOENT))
				goto out;

			nblocks = pmfs2_o2b_up(offset + iov_iter_count(ii));

			_unmap_maping(inode, index, nblocks, ii);

			err = pmfs2_pi_alloc_blocks(sb, pi, index, nblocks, 0);
			if (unlikely(err))
				goto out;

			err = pmfs2_get_data_block(sb, pi, index, rw, &gbi);
			if (unlikely(err))
				goto out;
		}

		retl = _copy_from_iter_nt(sb, &gbi, offset, len, ii);

		pmfs2_put_data_block(sb, &gbi);

		if (unlikely(retl != len)) {
			err = -EFAULT;
			break;
		}

		pos += len;
		++index;
		offset = 0;
	}

out:
	pmfs2_flush_pi(sb, pi);

	if (unlikely(pos == start))
		return err;

	kiocb->ki_pos = pos;
	return pos - start;
}

ssize_t pmfs2_rw_get_multy_write(struct super_block *sb, struct inode *inode,
				struct kiocb *kiocb, struct iov_iter *ii)
{
	struct pmfs2_inode *pi = pmfs2_pi(inode);
	loff_t start = kiocb->ki_pos;
	loff_t pos = start;
	ulong index = pmfs2_o2b(pos);
	uint offset = pos & (PMFS2_BLOCK_SIZE - 1);
	bool done_alloc = false;
	int err = 0;

	_zus_iom_start(&ii->iomb, NULL, NULL);

	while (iov_iter_count(ii)) {
		struct pmfs2_gbi gbi = {};
		uint len;
		uint rw = WRITE;
		bool full;

		gbi.iomb = &ii->iomb;

		len = min_t(uint, PMFS2_BLOCK_SIZE - offset,
				iov_iter_count(ii));
		err = pmfs2_get_data_block(sb, pi, index, rw, &gbi);

		if (err || !gbi.bn) {
			ulong nblocks;

			if (unlikely(err != -ENOENT))
				goto out;

			nblocks = pmfs2_o2b_up(offset + iov_iter_count(ii));

			_unmap_maping(inode, index, nblocks, ii);

			err = pmfs2_pi_alloc_blocks(sb, pi, index, nblocks, 0);
			if (unlikely(err))
				goto out;

			err = pmfs2_get_data_block(sb, pi, index, rw, &gbi);
			if (unlikely(err))
				goto out;

			done_alloc = true;
		}

		iov_iter_advance(ii, len);

		pos += len;
		++index;
		offset = 0;

		full = !_ziom_enc_t1_bn(gbi.iomb, gbi.bn, 0);
		if (full)
			break;
	}

out:
	pmfs2_flush_pi(sb, pi);

	if (unlikely(pos == start))
		return err;

	kiocb->ki_pos = pos;
	if (done_alloc)
		kiocb->ret_flags |=  ZUFS_RET_LOCKED_PUT;

	return pos - start;
}

void pmfs2_rw_put_multy(struct super_block *sb, struct inode *inode,
		       struct zufs_ioc_IO *io)
{
	struct pmfs2_gbi gbi = {};
	uint i;

	gbi.rw = io->rw;
	for (i = 0; i < io->ziom.iom_n; ++i) {
		gbi.bn = _zufs_iom_t1_bn(io->iom_e[i]);

		if (!gbi.bn)
			continue;

		if (unlikely(gbi.bn > pmfs2_t1_blocks(sb)))
			continue;
		pmfs2_put_data_block(sb, &gbi);
	}
}

ssize_t pmfs2_rw_get_multy_read(struct super_block *sb, struct inode *inode,
			       struct kiocb *kiocb, struct iov_iter *ii)
{
	struct pmfs2_inode *pi = pmfs2_pi(inode);
	struct file_ra_state *ra = kiocb_ra(kiocb);
	loff_t start = kiocb->ki_pos;
	loff_t pos = start;
	ulong index = pmfs2_o2b(pos);
	uint offset = pos & (PMFS2_BLOCK_SIZE - 1);
	int rw = READ;
	int err = 0;

	if (unlikely(pos > (long)le64_to_cpu(pi->i_size)))
		return 0;

	iov_iter_truncate(ii, le64_to_cpu(pi->i_size) - pos);
	if (unlikely(!iov_iter_count(ii) && !ra->ra_pages))
		return 0;

	_zus_iom_start(&ii->iomb, NULL, NULL);

	while (iov_iter_count(ii)) {
		struct pmfs2_gbi gbi = {};
		uint len;
		bool full;

		gbi.iomb = &ii->iomb;

		len = min_t(uint, PMFS2_BLOCK_SIZE - offset,
				iov_iter_count(ii));

		err = pmfs2_get_data_block(sb, pi, index, rw, &gbi);
		if (err == -ENOENT)
			err = 0;
		else if (unlikely(err))
			goto fail;

		iov_iter_advance(ii, len);

		pos += len;
		++index;
		offset = 0;

		full = !_ziom_enc_t1_bn(gbi.iomb, gbi.bn, 0);
		if (full)
			break;
	}

	if (start < (long)ra->prev_pos)
		ra->start = pmfs2_o2b(start);

	ra->prev_pos = pos - 1;
	kiocb->ki_pos = pos;

	return unlikely(pos == start) ? err : pos - start;

fail:
	return err;
}

int pmfs2_rw_fallocate(struct super_block *sb, struct inode *inode, int mode,
		      loff_t pos, loff_t end_pos, struct iov_iter *ii)
{
	struct pmfs2_inode *pi = pmfs2_pi(inode);
	loff_t len = (end_pos == LONG_MAX) ? LONG_MAX : end_pos - pos;
	loff_t i_size = (loff_t)pmfs2_pi_i_size(pi);
	uint offset = pos & (PMFS2_BLOCK_SIZE - 1);
	uint end_offset = end_pos & (PMFS2_BLOCK_SIZE - 1);

	if (mode & ~(ZUFS_FL_TRUNCATE))
		return -EOPNOTSUPP; /* TODO: support full fallocate */

	pmfs2_dbg_vfs("[%ld] i_size=%ld len=%ld offset=%u end_offset=%u\n",
		     pmfs2_pi_ino(pi), i_size, len, offset, end_offset);

	pmfs2_pi_truncate_size(sb, inode, pos);
	return 0;
}
