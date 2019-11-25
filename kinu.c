// SPDX-License-Identifier: GPL-2.0
/* See module.c for license details. */
#include <sys/uio.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>
#include <b-minmax.h>
#include "pmfs2.h"

/* iter */
#define iterate_iovec(i, n, __v, __p, skip, STEP) {		\
		size_t left;					\
		size_t wanted = n;				\
		__p = i->iov;					\
		__v.iov_len = min(n, __p->iov_len - skip);	\
		if (likely(__v.iov_len)) {			\
			__v.iov_base = __p->iov_base + skip;	\
			left = (STEP);				\
			__v.iov_len -= left;			\
			skip += __v.iov_len;			\
			n -= __v.iov_len;			\
		} else {					\
			left = 0;				\
		}						\
		while (unlikely(!left && n)) {			\
			__p++;					\
			__v.iov_len = min(n, __p->iov_len);	\
			if (unlikely(!__v.iov_len))		\
				continue;			\
			__v.iov_base = __p->iov_base;		\
			left = (STEP);				\
			__v.iov_len -= left;			\
			skip = __v.iov_len;			\
			n -= __v.iov_len;			\
		}						\
		n = wanted - n;					\
	}

#define iterate_and_advance(i, n, v, I, B, K) {			\
		size_t skip = i->iov_offset;			\
		{						\
			const struct iovec *iov;		\
			struct iovec v;				\
			iterate_iovec(i, n, v, iov, skip, (I))	\
			if (skip == iov->iov_len) {		\
				iov++;				\
				skip = 0;			\
			}					\
			i->nr_segs -= iov - i->iov;		\
			i->iov = iov;				\
		}						\
		i->count -= n;					\
		i->iov_offset = skip;				\
	}

static ulong  memcpy_skip(void *to, const void *from, ulong n)
{
	memcpy(to, from, n);
	return 0;
}

size_t copy_to_iter(const void *addr, size_t bytes, struct iov_iter *i)
{
	const char *from = addr;

	if (unlikely(bytes > i->count))
		bytes = i->count;

	if (unlikely(!bytes))
		return 0;

	iterate_and_advance(i, bytes, v,
			    memcpy_skip(v.iov_base,
					(from += v.iov_len) - v.iov_len,
					v.iov_len),
			    memcpy_to_page(v.bv_page, v.bv_offset,
					   (from += v.bv_len) - v.bv_len,
					   v.bv_len),
			    memcpy(v.iov_base,
				   (from += v.iov_len) - v.iov_len, v.iov_len)
			   )

	return bytes;
}

static ulong  memcpy_to_pmem_skip(void *to, const void *from, ulong n)
{
	memcpy_to_pmem(to, from, n);
	return 0;
}

size_t copy_from_iter_nocache(void *addr, size_t bytes, struct iov_iter *i)
{
	char *to = addr;

	if (unlikely(bytes > i->count))
		bytes = i->count;

	if (unlikely(!bytes))
		return 0;

	iterate_and_advance(i, bytes, v,
			    memcpy_to_pmem_skip((to += v.iov_len) - v.iov_len,
						v.iov_base, v.iov_len),
			    memcpy_from_page((to += v.bv_len) - v.bv_len,
					     v.bv_page, v.bv_offset, v.bv_len),
			    memcpy((to += v.iov_len) - v.iov_len,
				   v.iov_base, v.iov_len)
			   )

	return bytes;
}

static ulong memset_skip(void *to, int val, ulong n)
{
	memset(to, val, n);
	return 0;
}

size_t iov_iter_zero(size_t bytes, struct iov_iter *i)
{
	if (unlikely(bytes > i->count))
		bytes = i->count;

	if (unlikely(!bytes))
		return 0;

	iterate_and_advance(i, bytes, v,
			    memset_skip(v.iov_base, 0, v.iov_len),
			    memzero_page(v.bv_page, v.bv_offset, v.bv_len),
			    memset(v.iov_base, 0, v.iov_len)
			   )

	return bytes;
}

void iov_iter_advance(struct iov_iter *i, size_t size)
{
	iterate_and_advance(i, size, v, 0, 0, 0)
}


void iov_iter_init(struct iov_iter *i, const struct iovec *iov,
		   unsigned long nr_segs, size_t count)
{
	i->iov = iov;
	i->nr_segs = nr_segs;
	i->iov_offset = 0;
	i->count = count;
}

int iov_iter_init_single(struct iov_iter *i, void *buf, size_t len,
			 struct iovec *iov)
{
	iov->iov_base = buf;
	iov->iov_len = len;
	iov_iter_init(i, iov, 1, len);
	return 0;
}

ulong iov_iter_count(struct iov_iter *i)
{
	return i->count;
}

void iov_iter_truncate(struct iov_iter *i, ulong count)
{
	if (i->count > count)
		i->count = count;
}

void *pmfs2_malloc(size_t size)
{
	return zus_malloc(size);
}

void *pmfs2_calloc(size_t nmemb, size_t size)
{
	return zus_calloc(nmemb, size);
}

void *pmfs2_zalloc(size_t size)
{
	return pmfs2_calloc(1, size);
}

void pmfs2_free(void *ptr)
{
	zus_free(ptr);
}

static const char *_pr_tag(enum pmfs2_trace_channel ch)
{
	switch (ch) {
	case PMFS2_TRACE_INFO:
		return "info";
	case PMFS2_TRACE_WARN:
		return "warn";
	case PMFS2_TRACE_ERROR:
		return "error";
	case PMFS2_TRACE_VFS:
		return "vfs";
	case PMFS2_TRACE_RW:
		return "rw";
	case PMFS2_TRACE_RECON:
		return "recon";
	case PMFS2_TRACE_XATTR:
		return "xattr";
	case PMFS2_TRACE_VERBOS:
		return "verbos";
	default:
		break;
	}
	return "";
}

static const char *_pr_file(const char *path)
{
	const char *base = strrchr(path, '/');

	return likely(base) ? (base + 1) : path;
}

void pmfs2_pr(int dbg, enum pmfs2_trace_channel ch, const char *file, int line,
	      const char *func, const char *fmt, ...)
{
	va_list ap;
	FILE *fp = stdout;

	if (dbg && !ZUS_DBGPRNT)
		return;

	flockfile(fp);
	fprintf(fp, "%s [%s:%d %s] ", _pr_tag(ch), _pr_file(file), line, func);
	va_start(ap, fmt);
	vfprintf(stdout, fmt, ap);
	va_end(ap);
	funlockfile(fp);
}

int spin_lock_init(struct spinlock *sl)
{
	return pthread_spin_init(&sl->sl, 0);
}

void spin_lock_fini(struct spinlock *sl)
{
	pthread_spin_destroy(&sl->sl);
}

void spin_lock(struct spinlock *sl)
{
	int err;

	err = pthread_spin_lock(&sl->sl);
	BUG_ON(err);
}

void spin_unlock(struct spinlock *sl)
{
	int err;

	err = pthread_spin_unlock(&sl->sl);
	BUG_ON(err);
}

int spin_trylock(struct spinlock *sl)
{
	int err;

	err = pthread_spin_trylock(&sl->sl);
	BUG_ON(!err && (err != EBUSY));

	return -err;
}

int mutex_init(struct mutex *m)
{
	return pthread_mutex_init(&m->m, NULL);
}

void mutex_fini(struct mutex *m)
{
	pthread_mutex_destroy(&m->m);
}

void mutex_lock(struct mutex *m)
{
	pthread_mutex_lock(&m->m);
}

void mutex_unlock(struct mutex *m)
{
	pthread_mutex_unlock(&m->m);
}
