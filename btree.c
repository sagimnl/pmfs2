// SPDX-License-Identifier: GPL-2.0
/* See module.c for license details. */
#include "pmfs2.h"

static ulong _btree_root(struct pmfs2_inode *pi)
{
	return le64_to_cpu(pi->i_btree.root);
}

static uint _btree_height(struct pmfs2_inode *pi)
{
	return pi->i_btree.height;
}

static void _btree_set_root_and_height(struct pmfs2_inode *pi,
				       ulong bn, u8 height)
{
	/* TODO: Not crash proof; make me atomic */
	pi->i_btree.root = cpu_to_le64(bn);
	pi->i_btree.height = height;
}

static ulong __pmfs_find_data_block(struct super_block *sb,
				    struct pmfs2_inode *pi, ulong index)
{
	__le64 *level_ptr;
	ulong bn;
	uint bit_shift;
	uint level_index;
	u8 height;

	height = _btree_height(pi);
	bn = _btree_root(pi);

	while (height > 0) {
		level_ptr = pmfs2_baddr(sb, bn);
		bit_shift = (height - 1) * PMFS2_META_SHIFT;
		level_index = index >> bit_shift;
		bn = le64_to_cpu(level_ptr[level_index]);
		if (bn == 0)
			return 0;
		index = index & ((1 << bit_shift) - 1);
		height--;
	}
	return bn;
}

static ulong _find_data_block(struct super_block *sb, struct pmfs2_inode *pi,
			      ulong index)
{
	if (index >= (1UL << (_btree_height(pi) * PMFS2_META_SHIFT)))
		return 0;

	return __pmfs_find_data_block(sb, pi, index);
}

int pmfs2_get_data_block(struct super_block *sb, struct pmfs2_inode *pi,
			 ulong index, uint flags, struct pmfs2_gbi *gbi)
{
	ulong root_bn = _btree_root(pi);

	gbi->bn = 0;

	if (unlikely(!root_bn))
		return -ENOENT;

	/* get block using tree mapping */
	gbi->bn = _find_data_block(sb, pi, index);

	return gbi->bn ? 0 : -ENOENT;
}

void pmfs2_put_data_block(struct super_block *sb, struct pmfs2_gbi *gbi)
{
}

static int _increase_btree_height(struct super_block *sb,
				  struct pmfs2_inode *pi, u8 new_height)
{
	ulong prev_root = _btree_root(pi);
	u8 height = _btree_height(pi);
	__le64 *root;
	ulong blocknr;
	int err = 0;

	while (height < new_height) {
		/* allocate the meta block */
		err = pmfs2_new_block(sb, &blocknr, true);
		if (unlikely(err)) {
			pmfs2_err("failed to increase btree height => %d\n",
				  err);
			break;
		}
		root = pmfs2_baddr(sb, blocknr);
		root[0] = prev_root;
		pmfs2_flush_buffer(root, sizeof(*root));
		prev_root = cpu_to_le64(blocknr);
		height++;
	}
	_btree_set_root_and_height(pi, prev_root, height);
	return err;
}

static void _decrease_btree_height(struct super_block *sb,
				   struct pmfs2_inode *pi, ulong newsize,
				   ulong newroot)
{
	u8 height = _btree_height(pi);
	u8 new_height = 0;
	ulong bn, last_index;
	ulong *h, *r;

	if (pi->i_blocks == 0 || newsize == 0) {
		/* root must be NULL */
		BUG_ON(newroot != 0);
		goto update_root_and_height;
	}

	last_index = ((newsize + PMFS2_BLOCK_SIZE - 1) >> PMFS2_BLOCK_SHIFT) -
									1;
	while (last_index > 0) {
		last_index = last_index >> PMFS2_META_SHIFT;
		new_height++;
	}
	if (height == new_height)
		return;

	while (height > new_height) {
		/* freeing the meta block */
		__le64 *root = pmfs2_baddr(sb, newroot);

		bn = newroot;
		newroot = root[0];
		pmfs2_free_block(sb, bn);
		height--;
	}
update_root_and_height:
	/*
	 * pi->height and pi->root need to be atomically updated. use
	 * cmpxchg16 here. The following is dependent on a specific layout of
	 * inode fields
	 */
	r = (ulong *)&pi->i_btree.root;
	h = (ulong *)&pi->i_btree.height;
	/*
	 * TODO: the following function assumes cmpxchg16b instruction writes
	 * 16 bytes atomically. Confirm if it is really true.
	 */
	cmpxchg_double((ulong *)r, (ulong *)h, *(ulong *)r, *(ulong *)h,
		       newroot, new_height);
}

/*
 * recursive_alloc_blocks: recursively allocate a range of blocks from
 * first_blocknr to last_blocknr in the inode's btree.
 * Input:
 * block: points to the root of the b-tree where the blocks need to be allocated
 * height: height of the btree
 * first_blocknr: first block in the specified range
 * last_blocknr: last_blocknr in the specified range
 * zero: whether to zero-out the allocated block(s)
 */
static int recursive_alloc_blocks(struct super_block *sb,
				  struct pmfs2_inode *pi,
				  ulong bn, u8 height, ulong first_index,
				  ulong last_index, bool new_node, bool zero)
{
	__le64 *node = pmfs2_baddr(sb, bn);
	ulong new_bn, first_blk, last_blk;
	uint first_level_index, last_level_index;
	uint flush_bytes;
	uint node_bits;
	uint i;
	int err;

	node_bits = (height - 1) * PMFS2_META_SHIFT;

	first_level_index = first_index >> node_bits;
	last_level_index = last_index >> node_bits;

	for (i = first_level_index; i <= last_level_index; ++i) {
		if (height == 1) {
			if (node[i] == 0) {
				err = pmfs2_new_block(sb, &new_bn, zero);
				if (unlikely(err))
					return err;
				le64_add_cpu(&pi->i_blocks, 1);
				node[i] = cpu_to_le64(new_bn);
			}
		} else {
			if (node[i] == 0) {
				/* allocate the meta block */
				err = pmfs2_new_block(sb, &new_bn, zero);
				if (unlikely(err))
					goto fail;
				node[i] = cpu_to_le64(new_bn);
				new_node = 1;
			}

			first_blk = (i == first_level_index) ? (first_index &
				((1UL << node_bits) - 1)) : 0;

			last_blk = (i == last_level_index) ? (last_index &
				((1UL << node_bits) - 1)) :
					(1UL << node_bits) - 1;

			err = recursive_alloc_blocks(sb, pi,
						     le64_to_cpu(node[i]),
						     height - 1, first_blk,
						     last_blk, new_node, zero);
			if (unlikely(err < 0))
				goto fail;
		}
	}
	if (new_node) {
		/*
		 * if the changes were not logged, flush the cachelines we may
		 * have modified
		 */
		flush_bytes =
			(last_level_index - first_level_index + 1) *
				sizeof(node[0]);
		pmfs2_flush_buffer(&node[first_level_index], flush_bytes);
	}
	err = 0;
fail:
	return err;
}

int pmfs2_btree_alloc_blocks(struct super_block *sb, struct pmfs2_inode *pi,
			     ulong index, uint num, uint flags)
{
	ulong last_index, total_blocks, max_blocks;
	uint blk_shift;
	u8 height;
	int err;

	last_index = index + num - 1;

	pmfs2_dbg_verbose("alloc_blocks height %d index %lx num %x, "
			  "last_index 0x%lx\n", _btree_height(pi), index,
			  num, last_index);

	height = _btree_height(pi);
	blk_shift = height * PMFS2_META_SHIFT;
	max_blocks = 0x1UL << blk_shift;

	if (max_blocks - 1 < last_index) {
		/* B-tree height increases as a result of this allocation */
		total_blocks = last_index >> blk_shift;
		while (total_blocks > 0) {
			total_blocks = total_blocks >> PMFS2_META_SHIFT;
			height++;
		}
		if (height > 3) {
			err = -ENOSPC;
			goto fail;
		}
	}

	if (!_btree_root(pi)) {
		if (height == 0) {
			ulong bn;

			err = pmfs2_new_block(sb, &bn, true);
			if (unlikely(err))
				goto fail;

			le64_add_cpu(&pi->i_blocks, 1);
			_btree_set_root_and_height(pi, bn, height);
		} else {
			err = _increase_btree_height(sb, pi, height);
			if (unlikely(err))
				goto fail;

			err = recursive_alloc_blocks(sb, pi, _btree_root(pi),
						     height, index, last_index,
						     1, true);
			if (unlikely(err < 0))
				goto fail;
		}
	} else {
		/* Go forward only if the height of the tree is non-zero. */
		if (height == 0)
			return 0;

		if (_btree_height(pi) < height) {
			err = _increase_btree_height(sb, pi, height);
			if (unlikely(err))
				goto fail;
		}
		err = recursive_alloc_blocks(sb, pi, _btree_root(pi), height,
					     index, last_index, 0, true);
		if (unlikely(err < 0))
			goto fail;
	}
	return 0;
fail:
	return err;
}

int pmfs2_get_block_create(struct super_block *sb, struct pmfs2_inode *pi,
			   ulong index, uint write_flags, struct pmfs2_gbi *gbi)
{
	int err;

	err = pmfs2_get_data_block(sb, pi, index, WRITE | write_flags, gbi);
	if (unlikely(err < 0))
		return err;

	if (gbi->bn)
		return 0;

	err = pmfs2_pi_alloc_blocks(sb, pi, index, 1, 0);
	if (unlikely(err))
		return err;

	err = pmfs2_get_data_block(sb, pi, index, WRITE | write_flags, gbi);
	if (unlikely(err))
		return err;

	return 1;
}

/* examine the meta-data block node up to the end_idx for any non-null
 * pointers. if found return false, else return true.
 * required to determine if a meta-data block contains no pointers and hence
 * can be freed.
 */
static bool is_empty_meta_block(__le64 *node, uint start, uint end)
{
	uint i, last_index = (1 << PMFS2_META_SHIFT) - 1;

	for (i = 0; i < start; i++)
		if (unlikely(node[i]))
			return false;
	for (i = end + 1; i <= last_index; i++)
		if (unlikely(node[i]))
			return false;
	return true;
}

static int recursive_truncate_blocks(struct super_block *sb, ulong bn,
				     u8 height, ulong first_index,
				     ulong last_index, bool *meta_empty)
{
	ulong first_blk, last_blk;
	uint node_bits, first_level_index, last_level_index, i;
	__le64 *node = pmfs2_baddr(sb, bn);
	uint freed = 0, bzero;
	int start, end;
	bool mpty, all_range_freed = true;

	node_bits = (height - 1) * PMFS2_META_SHIFT;

	start = first_level_index = first_index >> node_bits;
	end = last_level_index = last_index >> node_bits;

	if (height == 1) {
		for (i = first_level_index; i <= last_level_index; ++i) {
			if (unlikely(!node[i]))
				continue;
			/* Freeing the data block */
			pmfs2_free_block(sb, le64_to_cpu(node[i]));
			freed++;
		}
	} else {
		for (i = first_level_index; i <= last_level_index; ++i) {
			if (unlikely(!node[i]))
				continue;
			first_blk = (i == first_level_index) ? (first_index &
				((1UL << node_bits) - 1)) : 0;

			last_blk = (i == last_level_index) ? (last_index &
				((1UL << node_bits) - 1)) :
					(1UL << node_bits) - 1;

			freed += recursive_truncate_blocks(sb,
							   le64_to_cpu(node[i]),
							   height - 1,
							   first_blk, last_blk,
							   &mpty);
			/* cond_resched(); */
			if (mpty) {
				/* Freeing the meta-data block */
				pmfs2_free_block(sb, le64_to_cpu(node[i]));
			} else {
				if (i == first_level_index)
					start++;
				else if (i == last_level_index)
					end--;
				all_range_freed = false;
			}
		}
	}
	if (all_range_freed &&
	    is_empty_meta_block(node, first_level_index, last_level_index)) {
		*meta_empty = true;
	} else {
		/* Zero-out the freed range if the meta-block in not empty */
		if (start <= end) {
			bzero = (end - start + 1) * sizeof(ulong);
			pmfs2_pmemzero(&node[start], bzero);
			pmfs2_flush_buffer(&node[start], bzero);
		}
		*meta_empty = false;
	}
	return freed;
}

/* Support for sparse files: even though pi->i_size may indicate a certain
 * last_blocknr, it may not be true for sparse files. Specifically, last_blocknr
 * can not be more than the maximum allowed by the inode's tree height.
 */
static ulong pmfs2_sparse_last_blocknr(u8 height, ulong index)
{
	if ((1UL << (height * PMFS2_META_SHIFT)) <= index)
		index = (1UL << (height * PMFS2_META_SHIFT)) - 1;
	return index;
}

void pmfs2_btree_truncate(struct super_block *sb, struct pmfs2_inode *pi,
			  ulong first_index, ulong last_index)
{
	uint freed = 0;
	ulong root;

	if (!_btree_root(pi))
		goto end_truncate_blocks;

	if (last_index == 0)
		goto end_truncate_blocks;

	last_index = pmfs2_sparse_last_blocknr(_btree_height(pi), last_index);

	if (last_index < first_index)
		goto end_truncate_blocks;

	root = _btree_root(pi);
	if (_btree_height(pi) == 0) {
		pmfs2_free_block(sb, root);
		root = 0;
		freed = 1;
	} else {
		bool mpty = false;

		freed = recursive_truncate_blocks(sb, root, _btree_height(pi),
						  first_index, last_index,
						  &mpty);
		if (mpty) {
			pmfs2_free_block(sb, root);
			root = 0;
		}
	}
	le64_add_cpu(&pi->i_blocks, -freed);
	_decrease_btree_height(sb, pi, first_index, root);
	pmfs2_flush_buffer(pi, sizeof(*pi));
	return;

end_truncate_blocks:
	/* we still need to update ctime and mtime */
	return;
}

static int _do_btree_recon(struct super_block *sb, ulong bn, uint height)
{
	ulong *node;
	int i, err;

	if (unlikely(!bn))
		return 0;

	err = pmfs2_mark_bn_active(sb, bn);
	if (unlikely(err))
		return err;

	if (height == 0)
		return 0;

	node = pmfs2_baddr(sb, bn);

	for (i = 0; i < PMFS2_META_LEVEL_SIZE; ++i) {
		err = _do_btree_recon(sb, le64_to_cpu(node[i]), height - 1);
		if (unlikely(err))
			return err;
	}
	return 0;
}

int pmfs2_btree_recon(struct super_block *sb, struct pmfs2_inode *pi)
{
	ulong root_bn;
	uint height;

	root_bn = _btree_root(pi);
	if (!root_bn)
		return 0;

	height = _btree_height(pi);
	if (unlikely(height > PMFS2_BTREE_HEIGHT_MAX))
		return -EFSCORRUPTED;

	return _do_btree_recon(sb, root_bn, height);
}
