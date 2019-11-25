// SPDX-License-Identifier: GPL-2.0
/* See module.c for license details. */

#include "pmfs2.h"

static ulong _page_to_bn(struct super_block *sb, struct page *page)
{
	struct multi_devices *md = PMFS2_SB(sb)->md;

	return md_page_to_bn(md, page);
}

static struct page *_bn_to_page(struct super_block *sb, ulong bn)
{
	return md_bn_to_page(PMFS2_SB(sb)->md, bn);
}

int pmfs2_init_free_list(struct super_block *sb)
{
	struct pmfs2_sb_info *sbi = PMFS2_SB(sb);
	struct pmfs2_list *pq = &sbi->s_free_pages_list;
	ulong t1_blocks;

	t1_blocks = md_t1_blocks(sbi->md);
	if (unlikely(t1_blocks < 1024)) {
		pmfs2_warn("t1_blocks=%lu\n", t1_blocks);
		return -EINVAL;
	}

	pq->md = sbi->md;
	pq->bn_max = t1_blocks;
	pq->size = 0;
	list_init(&pq->lru);

	return spin_lock_init(&pq->lock);
}

void pmfs2_fini_free_list(struct super_block *sb)
{
	struct pmfs2_sb_info *sbi = PMFS2_SB(sb);
	struct pmfs2_list *pq = &sbi->s_free_pages_list;

	spin_lock_fini(&pq->lock);
	list_init(&pq->lru);
	pq->size = 0;
	pq->bn_max = 0;
	pq->md = NULL;
}

void pmfs2_populate_all_freeq(struct super_block *sb)
{
	struct pmfs2_list *pq = &PMFS2_SB(sb)->s_free_pages_list;
	ulong bn;

	for (bn = 1; bn < pq->bn_max; ++bn) {
		struct page *page = _bn_to_page(sb, bn);

		memset(page, 0, sizeof(*page));
		list_init(&page->lru);
		list_add_tail(&page->lru, &pq->lru);
		pq->size++;
	}
}

int pmfs2_mark_bn_active(struct super_block *sb, ulong bn)
{
	struct pmfs2_list *pq;
	struct page *page;

	if (unlikely(!bn))
		return 0;

	page = _bn_to_page(sb, bn);
	if (unlikely(!page))
		return -EFSCORRUPTED;

	pq = &PMFS2_SB(sb)->s_free_pages_list;
	page->_refcount = 1;
	list_del_init(&page->lru);
	pq->size--;

	return 0;
}

int pmfs2_mark_addr_active(struct super_block *sb, void *addr)
{
	return pmfs2_mark_bn_active(sb, pmfs2_addr_to_bn(sb, addr));
}

static struct page *_alloc_block(struct super_block *sb)
{
	struct pmfs2_list *fpl = &PMFS2_SB(sb)->s_free_pages_list;
	struct page *page;

	spin_lock(&fpl->lock);

	if (unlikely(!fpl->size)) {
		spin_unlock(&fpl->lock);
		return NULL;
	}

	page = list_first_entry(&fpl->lru, typeof(*page), lru);
	list_del_init(&page->lru);
	WARN_ON(page->_refcount);
	page->_refcount = 1;
	fpl->size--;

	spin_unlock(&fpl->lock);

	return page;
}

int pmfs2_new_block(struct super_block *sb, ulong *bn, bool zero)
{
	struct page *page;

	page = _alloc_block(sb);
	if (unlikely(!page))
		return -ENOSPC;

	*bn = _page_to_bn(sb, page);
	if (zero)
		pmfs2_pmemzero(pmfs2_baddr(sb, *bn), PMFS2_BLOCK_SIZE);

	return 0;
}

void pmfs2_free_block(struct super_block *sb, ulong bn)
{
	struct page *page = _bn_to_page(sb, bn);
	struct pmfs2_list *fpl = &PMFS2_SB(sb)->s_free_pages_list;

	spin_lock(&fpl->lock);

	WARN_ON(page->_refcount != 1);
	page->_refcount = 0;
	list_add(&page->lru, &fpl->lru);
	fpl->size++;

	spin_unlock(&fpl->lock);
}
