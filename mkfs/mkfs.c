// SPDX-License-Identifier: GPL-2.0
/* See module.c for license details. */

#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>
#include <fcntl.h>
#include <unistd.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <errno.h>
#include <error.h>
#include <time.h>
#include <uuid/uuid.h>

#include "zus.h"
#include "pmfs2.h"


/* globals */
static const char *g_dev_path;
static uuid_t g_super_uuid;
static uuid_t g_dev_uuid;

static void _init_globals(const char *dev_path)
{
	g_dev_path = dev_path;
	uuid_generate(g_super_uuid);
	uuid_generate(g_dev_uuid);
}


static union pmfs2_meta_block *_alloc_meta_block(void)
{
	union pmfs2_meta_block *mb;

	mb = pmfs2_zalloc(sizeof(*mb));
	if (unlikely(!mb))
		error(EXIT_FAILURE, -1, "alloc meta-block failed");
	return mb;
}

static struct pmfs2_super_block *_alloc_super_block(void)
{
	union pmfs2_meta_block *mb = _alloc_meta_block();

	return &mb->sb;
}

static void _free_meta_block(union pmfs2_meta_block *mb)
{
	memset(mb, 0xFF, sizeof(*mb));
	pmfs2_free(mb);
}

static void _free_super_block(struct pmfs2_super_block *sb)
{
	_free_meta_block(container_of(sb, union pmfs2_meta_block, sb));
}

static int _open_blkdev(loff_t *sz)
{
	int fd, err;
	size_t bdev_size = 0, min_size = 1UL << 20;
	struct stat st;
	const char *path = g_dev_path;

	fd = open(path, O_RDWR);
	if (fd <= 0)
		error(EXIT_FAILURE, -errno, "open failed: %s", path);

	err = fstat(fd, &st);
	if (err)
		error(EXIT_FAILURE, -errno, "fstat failed: %s", path);

	if (!S_ISBLK(st.st_mode))
		error(EXIT_FAILURE, -1, "not a block device: %s", path);

	err = ioctl(fd, BLKGETSIZE64, &bdev_size);
	if (err)
		error(EXIT_FAILURE, err, "BLKGETSIZE64 failed: %s", path);

	if (bdev_size < min_size)
		error(EXIT_FAILURE, 0, "illegal device size: %s %lu",
		      path, bdev_size);

	*sz = (loff_t)bdev_size;
	return fd;
}

static void _close_blkdev(int fd)
{
	int err;
	const char *path = g_dev_path;

	err = fsync(fd);
	if (err)
		error(EXIT_FAILURE, -errno, "fsync failed: %s", path);
	close(fd);
}

static void _fill_itable(struct pmfs2_inode *it_pi)
{
	struct timespec now;

	clock_gettime(CLOCK_REALTIME, &now);
	memset(it_pi, 0, sizeof(*it_pi));
	it_pi->i_mode = cpu_to_le16(0755);
	it_pi->i_uid = cpu_to_le32(geteuid());
	it_pi->i_gid = cpu_to_le32(getegid());
	pmfs2_timespec_to_le64(&it_pi->i_atime, &now);
	pmfs2_timespec_to_le64(&it_pi->i_mtime, &now);
	pmfs2_timespec_to_le64(&it_pi->i_ctime, &now);
}

static void _fill_mdt(struct md_dev_table *mdt, ulong t1_blocks)
{
	struct timespec now;
	struct md_dev_id *dev_id;
	ushort version = (PMFS2_MAJOR_VERSION * ZUFS_MINORS_PER_MAJOR) +
			 PMFS2_MINOR_VERSION;

	memset(mdt, 0, sizeof(*mdt));
	memcpy(&mdt->s_uuid, g_super_uuid, sizeof(mdt->s_uuid));
	mdt->s_version = cpu_to_le16(version);
	mdt->s_magic = cpu_to_le32(PMFS2_SUPER_MAGIC);
	mdt->s_flags = cpu_to_le64(0);
	mdt->s_t1_blocks = cpu_to_le64(t1_blocks);
	mdt->s_dev_list.id_index = cpu_to_le16(0);
	mdt->s_dev_list.t1_count = cpu_to_le16(1);

	dev_id = &mdt->s_dev_list.dev_ids[0];
	memcpy(&dev_id->uuid, g_dev_uuid, sizeof(dev_id->uuid));
	dev_id->blocks = mdt->s_t1_blocks;

	clock_gettime(CLOCK_REALTIME, &now);
	timespec_to_zt(&mdt->s_wtime, &now);
	mdt->s_sum = cpu_to_le16(md_calc_csum(mdt));
}

static ulong _device_t1_blocks(loff_t dev_size)
{
	ulong align_mask = ZUFS_ALLOC_MASK;

	return md_o2p(dev_size & ~align_mask);
}

static void _fill_super_block(struct pmfs2_super_block *sb, ulong t1_blocks)
{
	_fill_mdt(&sb->s_mdt, t1_blocks);
	_fill_itable(&sb->s_itable);
}

static void _write_super_block(int fd, const struct pmfs2_super_block *sb)
{
	int err;
	size_t bsz = PMFS2_BLOCK_SIZE;

	err = pwrite(fd, sb, bsz, 0);
	if (err != (int)bsz)
		error(EXIT_FAILURE, -errno, "failed to write super block");
}

int main(int argc, char *argv[])
{
	int err, fd;
	loff_t dev_size = 0;
	struct pmfs2_super_block *sb;

	if (argc != 2)
		error(EXIT_FAILURE, -1, "usage: mkfs <device-path>");

	err = zus_slab_init();
	if (unlikely(err))
		error(EXIT_FAILURE, -1, "slab init failed");

	_init_globals(argv[1]);
	fd = _open_blkdev(&dev_size);

	sb = _alloc_super_block();
	_fill_super_block(sb, _device_t1_blocks(dev_size));

	_write_super_block(fd, sb);
	_close_blkdev(fd);

	_free_super_block(sb);
	zus_slab_fini();

	return 0;
}


