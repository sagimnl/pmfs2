/* SPDX-License-Identifier: GPL-2.0 */
/* See module.c for license details. */
#ifndef _PMFS2_KINU_H_
#define _PMFS2_KINU_H_

/*
 * Kernel in User-space: bring Linux kernel fs types into user-space.
 */
#include <unistd.h>
#include <errno.h>
#include <pthread.h>
#include <iom_enc.h>


/* utlity macros */
#ifndef WARN_ON
#define WARN_ON(x_)		ZUS_WARN_ON(x_)
#endif
#ifndef BUG_ON
#define BUG_ON(x_)		ZUS_BUG_ON(x_)
#endif
#ifndef BUILD_BUG_ON
#define BUILD_BUG_ON(x_)	_Static_assert(!(x_), #x_)
#endif
#ifndef ARRAY_SIZE
#define ARRAY_SIZE(x_)		(sizeof(x_) / sizeof(x_[0]))
#endif

#define __cmpxchg_double(pfx, p1, p2, o1, o2, n1, n2)			\
({									\
	bool __ret;							\
	__typeof__(*(p1)) __old1 = (o1), __new1 = (n1);			\
	__typeof__(*(p2)) __old2 = (o2), __new2 = (n2);			\
	BUILD_BUG_ON(sizeof(*(p1)) != sizeof(long));			\
	BUILD_BUG_ON(sizeof(*(p2)) != sizeof(long));			\
	BUG_ON((unsigned long)(p1) % (2 * sizeof(long)));		\
	BUG_ON((unsigned long)((p1) + 1) != (unsigned long)(p2));	\
	asm volatile(pfx "cmpxchg%c4b %2; sete %0"			\
		     : "=a" (__ret), "+d" (__old2),			\
		       "+m" (*(p1)), "+m" (*(p2))			\
		     : "i" (2 * sizeof(long)), "a" (__old1),		\
		       "b" (__new1), "c" (__new2));			\
	__ret;								\
})

#define cmpxchg_double(p1, p2, o1, o2, n1, n2) \
	__cmpxchg_double(, p1, p2, o1, o2, n1, n2)

#define list_init		a_list_init
#define list_head		a_list_head
#define list_add		a_list_add
#define list_add_tail		a_list_add_tail
#define list_del		a_list_del
#define list_del_init		a_list_del_init
#define list_first_entry	a_list_first_entry

/* Special errno codes (a-la XFS) */
#define EFSCORRUPTED		EUCLEAN

/* generic data direction definitions */
#define READ			0
#define WRITE			1

struct page {
	/* First double word */
	unsigned long		flags;
	void			*s_mem;

	/* Second double word */
	long			index;
	int			units;
	int			_refcount;

	/* Third double word */
	struct list_head	lru;

	/* Forth double word */
	unsigned long		private;
	void			*mem_cgroup;

} __aligned(64);


struct spinlock {
	pthread_spinlock_t sl;
};
typedef struct spinlock spinlock_t;

struct mutex {
	pthread_mutex_t m;
};

struct rwlock {
	pthread_rwlock_t rwl;
};

struct super_block {
	void *s_fs_info;
};

struct inode {
	spinlock_t i_lock;
};

struct qstr {
	unsigned int len;
	const char *name;
};


#define file_ra_state __zufs_ra

#define IOCB_EVENTFD	ZUFS_RW_EVENTFD
#define IOCB_APPEND	ZUFS_RW_APPEND
#define IOCB_DIRECT	ZUFS_RW_DIRECT
#define IOCB_HIPRI	ZUFS_RW_HIPRI
#define IOCB_DSYNC	ZUFS_RW_DSYNC
#define IOCB_SYNC	ZUFS_RW_SYNC
#define IOCB_WRITE	ZUFS_RW_WRITE
#define IOCB_NOWAIT	ZUFS_RW_NOWAIT
#define IOCB_RAND	ZUFS_RW_RAND
#define IOCB_PRE_READ	(ZUFS_RW_USER << 0)

struct kiocb {
	struct file_ra_state	*ra;
	loff_t			ki_pos;
	__u64			ki_flags;

	__u32			ret_flags;	/* Added for zufs */
};


struct iov_iter {
	size_t iov_offset;
	size_t count;
	const struct iovec *iov;
	unsigned long nr_segs;
	struct __zufs_write_unmap *unmap;

	struct zus_iomap_build	iomb;
};


void iov_iter_init(struct iov_iter *i, const struct iovec *iov,
		   unsigned long nr_segs, size_t count);
int iov_iter_init_single(struct iov_iter *i, void *buf, size_t len,
			 struct iovec *iov);
ulong iov_iter_count(struct iov_iter *i);
void iov_iter_truncate(struct iov_iter *i, ulong count);
size_t iov_iter_zero(size_t len, struct iov_iter *i);
size_t copy_to_iter(const void *addr, size_t bytes, struct iov_iter *i);
size_t copy_from_iter_nocache(void *addr, size_t bytes, struct iov_iter *i);
void iov_iter_advance(struct iov_iter *i, size_t size);


int mutex_init(struct mutex *m);
void mutex_fini(struct mutex *m);
void mutex_lock(struct mutex *m);
void mutex_unlock(struct mutex *m);

int spin_lock_init(struct spinlock *sl);
void spin_lock_fini(struct spinlock *sl);
void spin_lock(struct spinlock *sl);
void spin_unlock(struct spinlock *sl);
int spin_trylock(struct spinlock *sl);


#define MAX_ERRNO	4095

#define IS_ERR_VALUE(x) \
	unlikely((unsigned long)(void *)(x) >= (unsigned long)-MAX_ERRNO)

static inline void *ERR_PTR(long error)
{
	return (void *)error;
}

static inline long PTR_ERR(const void *ptr)
{
	return (long) ptr;
}

static inline bool IS_ERR(const void *ptr)
{
	return IS_ERR_VALUE((unsigned long)ptr);
}

static inline bool IS_ERR_OR_NULL(const void *ptr)
{
	return (!ptr || IS_ERR(ptr));
}

static inline int PTR_ERR_OR_ZERO(const void *ptr)
{
	if (IS_ERR(ptr))
		return (int)PTR_ERR(ptr);
	else
		return 0;
}

static inline void le64_add_cpu(__le64 *var, ulong val)
{
	*var = cpu_to_le64(le64_to_cpu(*var) + val);
}

static inline void le32_add_cpu(__le32 *var, uint val)
{
	*var = cpu_to_le32(le32_to_cpu(*var) + val);
}

#endif /* _PMFS2_KINU_H_ */
