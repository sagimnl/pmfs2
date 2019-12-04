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

struct pmfs2_pdev_info {
	char *path;
	uuid_t uuid;
	loff_t size;
	ulong blocks;
	short index;
	int fd;
};

struct pmfs2_mkfs_info {
	struct timespec now;
	uuid_t super_uuid;
	ulong t1_blocks;
	ushort version;
	int ndevs;
	struct pmfs2_pdev_info pdi[MD_DEV_MAX];
};


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

static int _open_blkdev(const char *path, loff_t *sz)
{
	int fd, err;
	size_t bdev_size = 0, min_size = 1UL << 20;
	struct stat st;

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

static void _close_blkdev(const char *path, int fd)
{
	int err;

	err = fsync(fd);
	if (err)
		error(EXIT_FAILURE, -errno, "fsync failed: %s", path);
	close(fd);
}

static void _fill_itable(struct pmfs2_inode *it_pi, struct pmfs2_mkfs_info *mki)
{
	memset(it_pi, 0, sizeof(*it_pi));
	it_pi->i_mode = cpu_to_le16(0755);
	it_pi->i_uid = cpu_to_le32(geteuid());
	it_pi->i_gid = cpu_to_le32(getegid());
	pmfs2_timespec_to_le64(&it_pi->i_atime, &mki->now);
	pmfs2_timespec_to_le64(&it_pi->i_mtime, &mki->now);
	pmfs2_timespec_to_le64(&it_pi->i_ctime, &mki->now);
}

static void _fill_mdt(struct md_dev_table *mdt, struct pmfs2_mkfs_info *mki)
{
	memset(mdt, 0, sizeof(*mdt));
	memcpy(&mdt->s_uuid, mki->super_uuid, sizeof(mdt->s_uuid));
	mdt->s_version = cpu_to_le16(mki->version);
	mdt->s_magic = cpu_to_le32(PMFS2_SUPER_MAGIC);
	mdt->s_flags = cpu_to_le64(0);
	mdt->s_t1_blocks = cpu_to_le64(mki->t1_blocks);
	mdt->s_dev_list.t1_count = cpu_to_le16(mki->ndevs);
	timespec_to_zt(&mdt->s_wtime, &mki->now);
}

static void _update_mdt_dev(struct md_dev_table *mdt,
			    struct pmfs2_mkfs_info *mki, short dev_index)
{
	struct md_dev_id *dev_id = &mdt->s_dev_list.dev_ids[dev_index];
	struct pmfs2_pdev_info *pdi = &mki->pdi[dev_index];

	memcpy(&dev_id->uuid, pdi->uuid, sizeof(dev_id->uuid));
	dev_id->blocks = cpu_to_le64(pdi->blocks);
}

static void _restamp_mdt(struct md_dev_table *mdt)
{
	mdt->s_sum = cpu_to_le16(md_calc_csum(mdt));
}

static void _fill_super_block(struct pmfs2_mkfs_info *mki,
			      struct pmfs2_super_block *sb)
{
	_fill_mdt(&sb->s_mdt, mki);
	_fill_itable(&sb->s_itable, mki);
}

static ulong _size_to_t1_blocks(loff_t dev_size)
{
	ulong align_mask = ZUFS_ALLOC_MASK;

	return md_o2p(dev_size & ~align_mask);
}

static struct pmfs2_mkfs_info *_init_mkfs_info(char *devs[], int ndevs)
{
	int i;
	struct pmfs2_mkfs_info *mki;

	mki = pmfs2_calloc(1, sizeof(*mki));
	if (unlikely(!mki))
		error(EXIT_FAILURE, -errno, "alloc failure");

	clock_gettime(CLOCK_REALTIME, &mki->now);
	uuid_generate(mki->super_uuid);
	mki->version = (PMFS2_MAJOR_VERSION * ZUFS_MINORS_PER_MAJOR) +
			PMFS2_MINOR_VERSION;

	for (i = 0; i < ndevs; ++i) {
		struct pmfs2_pdev_info *pdi = &mki->pdi[i];

		uuid_generate(pdi->uuid);
		pdi->path = realpath(devs[i], NULL);
		if (unlikely(!pdi->path))
			error(EXIT_FAILURE, 0, "no realpath: %s", devs[i]);

		pdi->index = i;
		pdi->fd = _open_blkdev(pdi->path, &pdi->size);
		pdi->blocks = _size_to_t1_blocks(pdi->size);
		mki->t1_blocks += pdi->blocks;
	}
	mki->ndevs = ndevs;
	return mki;
}

static void _fini_mkfs_info(struct pmfs2_mkfs_info *mki)
{
	int i;

	for (i = 0; i < mki->ndevs; ++i) {
		_close_blkdev(mki->pdi[i].path, mki->pdi[i].fd);
		free(mki->pdi[i].path);
	}
	pmfs2_free(mki);
}

static void _update_mdt_devs(struct pmfs2_mkfs_info *mki,
			     struct pmfs2_super_block *sb)
{
	int i;

	for (i = 0; i < mki->ndevs; ++i) {
		_update_mdt_dev(&sb->s_mdt, mki, (short)i);
	}
}

static void _write_super_blocks(struct pmfs2_mkfs_info *mki,
				struct pmfs2_super_block *sb)
{
	int i, err;

	for (i = 0; i < mki->ndevs; ++i) {
		_restamp_mdt(&sb->s_mdt);
		err = pwrite(mki->pdi[i].fd, sb, PMFS2_BLOCK_SIZE, 0);
		if (err != (int)PMFS2_BLOCK_SIZE)
			error(EXIT_FAILURE, -errno, "failed to write sb");
	}
}

/*
 * Hackish code to add proper symbolic-links when operating in multi-device
 * mode. Unfortunately, it does not  reboot.
 *
 * TODO: use udev rules
 */
static void _setup_by_uuid_symlink(struct pmfs2_mkfs_info *mki)
{
	int i;
	size_t len;
	char uu[40];
	char linkpath[256] = "/dev/disk/by-uuid/";

	if (mki->ndevs <= 1)
		return;

	len = strlen(linkpath);
	for (i = 0; i < mki->ndevs; ++i) {
		uuid_unparse(mki->pdi[i].uuid, uu);

		linkpath[len] = '\0';
		strcat(linkpath + len, uu);
		symlink(mki->pdi[i].path, linkpath);
	}
}

int main(int argc, char *argv[])
{
	int err;
	struct pmfs2_mkfs_info *mki;
	struct pmfs2_super_block *sb;

	if (argc < 2)
		error(EXIT_FAILURE, -1, "usage: mkfs <pmem0> [<pmem1>...]");

	if ((argc - 1) > MD_DEV_MAX)
		error(EXIT_FAILURE, -1, "too many devices");

	err = zus_slab_init();
	if (unlikely(err))
		error(EXIT_FAILURE, -1, "slab init failed");

	mki = _init_mkfs_info(argv + 1, argc - 1);
	sb = _alloc_super_block();

	_fill_super_block(mki, sb);
	_update_mdt_devs(mki, sb);
	_write_super_blocks(mki, sb);
	_setup_by_uuid_symlink(mki);

	_free_super_block(sb);
	_fini_mkfs_info(mki);
	zus_slab_fini();

	return 0;
}


