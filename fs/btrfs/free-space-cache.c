/*
 * Copyright (C) 2008 Red Hat.  All rights reserved.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License v2 as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public
 * License along with this program; if not, write to the
 * Free Software Foundation, Inc., 59 Temple Place - Suite 330,
 * Boston, MA 021110-1307, USA.
 */

#include <linux/pagemap.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/math64.h>
#include <linux/ratelimit.h>
#include "ctree.h"
#include "free-space-cache.h"
#include "transaction.h"
#include "disk-io.h"
#include "extent_io.h"
#include "inode-map.h"
#include "math.h"

#define BITMAP_SIZE			(BTRFS_SC_BLOCK_SIZE)
#define BITMAP_SIZE_SHIFT		(BTRFS_SC_BLOCK_SIZE_SHIFT)
#define BITS_PER_BITMAP			(BITMAP_SIZE << 3)
#define BITS_PER_BITMAP_SHIFT		(BITMAP_SIZE_SHIFT + 3)
#define BYTES_PER_BITMAP(ctl)		(BITS_PER_BITMAP << ctl->unit_shift)
#define BYTES_PER_BITMAP_SHIFT(ctl)	(BITS_PER_BITMAP_SHIFT + \
					 ctl->unit_shift)
#define BLOCKS_PER_PAGE			(1 << (PAGE_CACHE_SHIFT -	\
					       BTRFS_SC_BLOCK_SIZE_SHIFT))
#define MAX_CACHE_BYTES_PER_GIG(ctl)	(1 << (30 - ctl->unit_shift -	\
					       BITS_PER_BITMAP_SHIFT +	\
					       BTRFS_SC_BLOCK_SIZE_SHIFT))

static int link_free_space(struct btrfs_free_space_ctl *ctl,
			   struct btrfs_free_space *info);
static void __unlink_free_space(struct btrfs_free_space_ctl *ctl,
				struct btrfs_free_space *info);

struct inode *btrfs_lookup_cache_inode(struct btrfs_root *root,
				       struct btrfs_path *path,
				       u64 offset)
{
	struct btrfs_key key;
	struct btrfs_key location;
	struct btrfs_disk_key disk_key;
	struct btrfs_free_space_header *header;
	struct extent_buffer *leaf;
	struct inode *inode = NULL;
	int ret;

	key.objectid = BTRFS_FREE_SPACE_OBJECTID;
	key.offset = offset;
	key.type = 0;

	ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
	if (ret < 0)
		return ERR_PTR(ret);
	if (ret > 0) {
		btrfs_release_path(path);
		return ERR_PTR(-ENOENT);
	}

	leaf = path->nodes[0];
	header = btrfs_item_ptr(leaf, path->slots[0],
				struct btrfs_free_space_header);
	btrfs_free_space_key(leaf, header, &disk_key);
	btrfs_disk_key_to_cpu(&location, &disk_key);
	btrfs_release_path(path);

	inode = btrfs_iget(root->fs_info->sb, &location, root, NULL);
	if (!inode)
		return ERR_PTR(-ENOENT);
	if (IS_ERR(inode))
		return inode;
	if (is_bad_inode(inode)) {
		iput(inode);
		return ERR_PTR(-ENOENT);
	}

	mapping_set_gfp_mask(inode->i_mapping,
			mapping_gfp_mask(inode->i_mapping) & ~__GFP_FS);

	return inode;
}

struct inode *btrfs_lookup_free_space_inode(struct btrfs_root *root,
					    struct btrfs_block_group_cache *bg,
					    struct btrfs_path *path)
{
	struct inode *inode = NULL;
	u32 flags = BTRFS_INODE_NODATASUM | BTRFS_INODE_NODATACOW;

	spin_lock(&bg->lock);
	if (bg->inode)
		inode = igrab(bg->inode);
	spin_unlock(&bg->lock);
	if (inode)
		return inode;

	inode = btrfs_lookup_cache_inode(root, path,
					 bg->key.objectid);
	if (IS_ERR(inode))
		return inode;

	spin_lock(&bg->lock);
	if (!((BTRFS_I(inode)->flags & flags) == flags)) {
		printk(KERN_INFO "Old style space inode found, converting.\n");
		BTRFS_I(inode)->flags |= BTRFS_INODE_NODATASUM |
			BTRFS_INODE_NODATACOW;
		bg->disk_cache_state = BTRFS_DC_CLEAR;
	}

	if (!bg->iref) {
		bg->inode = igrab(inode);
		bg->iref = 1;
	}
	spin_unlock(&bg->lock);

	return inode;
}

int btrfs_create_cache_inode(struct btrfs_root *root,
			     struct btrfs_trans_handle *trans,
			     struct btrfs_path *path, u64 ino, u64 offset)
{
	struct btrfs_key key;
	struct btrfs_disk_key disk_key;
	struct btrfs_free_space_header *header;
	struct btrfs_inode_item *inode_item;
	struct extent_buffer *leaf;
	u64 flags = BTRFS_INODE_NOCOMPRESS | BTRFS_INODE_PREALLOC;
	int ret;

	ret = btrfs_insert_empty_inode(trans, root, path, ino);
	if (ret)
		return ret;

	/* We inline crc's for the free disk space cache */
	if (ino != BTRFS_FREE_INO_OBJECTID)
		flags |= BTRFS_INODE_NODATASUM | BTRFS_INODE_NODATACOW;

	leaf = path->nodes[0];
	inode_item = btrfs_item_ptr(leaf, path->slots[0],
				    struct btrfs_inode_item);
	btrfs_item_key(leaf, &disk_key, path->slots[0]);
	memset_extent_buffer(leaf, 0, (unsigned long)inode_item,
			     sizeof(*inode_item));
	btrfs_set_inode_generation(leaf, inode_item, trans->transid);
	btrfs_set_inode_size(leaf, inode_item, 0);
	btrfs_set_inode_nbytes(leaf, inode_item, 0);
	btrfs_set_inode_uid(leaf, inode_item, 0);
	btrfs_set_inode_gid(leaf, inode_item, 0);
	btrfs_set_inode_mode(leaf, inode_item, S_IFREG | 0600);
	btrfs_set_inode_flags(leaf, inode_item, flags);
	btrfs_set_inode_nlink(leaf, inode_item, 1);
	btrfs_set_inode_transid(leaf, inode_item, trans->transid);
	btrfs_set_inode_block_group(leaf, inode_item, offset);
	btrfs_mark_buffer_dirty(leaf);
	btrfs_release_path(path);

	key.objectid = BTRFS_FREE_SPACE_OBJECTID;
	key.offset = offset;
	key.type = 0;

	ret = btrfs_insert_empty_item(trans, root, path, &key,
				      sizeof(struct btrfs_free_space_header));
	if (ret < 0) {
		btrfs_release_path(path);
		return ret;
	}
	leaf = path->nodes[0];
	header = btrfs_item_ptr(leaf, path->slots[0],
				struct btrfs_free_space_header);
	memset_extent_buffer(leaf, 0, (unsigned long)header, sizeof(*header));
	btrfs_set_free_space_key(leaf, header, &disk_key);
	btrfs_mark_buffer_dirty(leaf);
	btrfs_release_path(path);

	return 0;
}

int btrfs_create_free_space_inode(struct btrfs_root *root,
				  struct btrfs_trans_handle *trans,
				  struct btrfs_block_group_cache *block_group,
				  struct btrfs_path *path)
{
	int ret;
	u64 ino;

	ret = btrfs_find_free_objectid(root, &ino);
	if (ret < 0)
		return ret;

	return btrfs_create_cache_inode(root, trans, path, ino,
					block_group->key.objectid);
}

int btrfs_truncate_cache(struct btrfs_root *root,
			 struct btrfs_trans_handle *trans,
			 struct btrfs_path *path,
			 struct inode *inode)
{
	struct btrfs_block_rsv *rsv;
	u64 needed_bytes;
	loff_t oldsize;
	int ret = 0;

	rsv = trans->block_rsv;
	trans->block_rsv = &root->fs_info->global_block_rsv;

	/* 1 for slack space, 1 for updating the inode */
	needed_bytes = btrfs_calc_trunc_metadata_size(root, 1) +
		btrfs_calc_trans_metadata_size(root, 1);

	spin_lock(&trans->block_rsv->lock);
	if (trans->block_rsv->reserved < needed_bytes) {
		spin_unlock(&trans->block_rsv->lock);
		trans->block_rsv = rsv;
		return -ENOSPC;
	}
	spin_unlock(&trans->block_rsv->lock);

	oldsize = i_size_read(inode);
	btrfs_i_size_write(inode, 0);
	truncate_pagecache(inode, oldsize, 0);

	/*
	 * We don't need an orphan item because truncating the free space cache
	 * will never be split across transactions.
	 */
	ret = btrfs_truncate_inode_items(trans, root, inode,
					 0, BTRFS_EXTENT_DATA_KEY);

	if (ret) {
		trans->block_rsv = rsv;
		btrfs_abort_transaction(trans, root, ret);
		return ret;
	}

	ret = btrfs_update_inode(trans, root, inode);
	if (ret)
		btrfs_abort_transaction(trans, root, ret);
	trans->block_rsv = rsv;

	return ret;
}

static int readahead_cache(struct inode *inode)
{
	struct file_ra_state *ra;
	unsigned long last_index;

	ra = kzalloc(sizeof(*ra), GFP_NOFS);
	if (!ra)
		return -ENOMEM;

	file_ra_state_init(ra, inode->i_mapping);
	last_index = (i_size_read(inode) - 1) >> PAGE_CACHE_SHIFT;

	page_cache_sync_readahead(inode->i_mapping, ra, NULL, 0, last_index);

	kfree(ra);

	return 0;
}

struct io_ctl {
	void *cur;
	void *orig;
	__le32 *crcs;
	struct page *page;
	struct page **pages;
	struct btrfs_root *root;
	int size;
	int page_index;
	int num_pages;
	int block_index;
	int num_blocks;
	unsigned check_crcs:1;
};

static int io_ctl_init(struct io_ctl *io_ctl, struct inode *inode,
		       struct btrfs_root *root)
{
	memset(io_ctl, 0, sizeof(struct io_ctl));
	io_ctl->num_pages = DIV_ROUND_UP_SHIFT(i_size_read(inode),
					       PAGE_CACHE_SHIFT);
	io_ctl->num_blocks = io_ctl->num_pages <<
			     (PAGE_CACHE_SHIFT - BTRFS_SC_BLOCK_SIZE_SHIFT);
	io_ctl->pages = kzalloc(sizeof(struct page *) * io_ctl->num_pages,
				GFP_NOFS);
	if (!io_ctl->pages)
		return -ENOMEM;
	io_ctl->root = root;
	if (btrfs_ino(inode) != BTRFS_FREE_INO_OBJECTID)
		io_ctl->check_crcs = 1;
	return 0;
}

static void io_ctl_free(struct io_ctl *io_ctl)
{
	kfree(io_ctl->pages);
}

static void io_ctl_unmap_page(struct io_ctl *io_ctl)
{
	if (io_ctl->cur) {
		kunmap(io_ctl->page);
		io_ctl->cur = NULL;
		io_ctl->orig = NULL;
	}
}

static void io_ctl_map_page(struct io_ctl *io_ctl)
{
	BUG_ON(io_ctl->page_index >= io_ctl->num_pages);
	io_ctl->page = io_ctl->pages[io_ctl->page_index++];
	io_ctl->cur = kmap(io_ctl->page);
	io_ctl->orig = io_ctl->cur;
	io_ctl->size = BTRFS_SC_BLOCK_SIZE;
}

static void io_ctl_drop_pages(struct io_ctl *io_ctl)
{
	int i;

	io_ctl_unmap_page(io_ctl);

	if (io_ctl->crcs)
		kunmap(io_ctl->pages[0]);

	for (i = 0; i < io_ctl->num_pages; i++) {
		if (io_ctl->pages[i]) {
			ClearPageChecked(io_ctl->pages[i]);
			unlock_page(io_ctl->pages[i]);
			page_cache_release(io_ctl->pages[i]);
		}
	}
}

static int io_ctl_prepare_pages(struct io_ctl *io_ctl, struct inode *inode,
				int uptodate)
{
	struct page *page;
	gfp_t mask = btrfs_alloc_write_mask(inode->i_mapping);
	int i;

	for (i = 0; i < io_ctl->num_pages; i++) {
		page = find_or_create_page(inode->i_mapping, i, mask);
		if (!page) {
			io_ctl_drop_pages(io_ctl);
			return -ENOMEM;
		}
		io_ctl->pages[i] = page;
		if (uptodate && !PageUptodate(page)) {
			btrfs_readpage(NULL, page);
			lock_page(page);
			if (!PageUptodate(page)) {
				printk(KERN_ERR "btrfs: error reading free "
				       "space cache\n");
				io_ctl_drop_pages(io_ctl);
				return -EIO;
			}
		}
	}

	for (i = 0; i < io_ctl->num_pages; i++) {
		clear_page_dirty_for_io(io_ctl->pages[i]);
		set_page_extent_mapped(io_ctl->pages[i]);
	}

	if (io_ctl->check_crcs)
		io_ctl->crcs = kmap(io_ctl->pages[0]);
	return 0;
}

static void io_ctl_set_crc(struct io_ctl *io_ctl, int index)
{
	u32 crc = ~(u32)0;
	unsigned offset = 0;

	if (!io_ctl->check_crcs)
		return;

	if (index == 0) {
		offset = sizeof(u32) * io_ctl->num_blocks;
		/*
		 * The current page is full of CRCs, we have skipped it
		 * in the caller.
		 */
		BUG_ON(unlikely(BTRFS_SC_BLOCK_SIZE - offset < sizeof(u64)));
	}

	crc = btrfs_csum_data(io_ctl->root, io_ctl->orig + offset, crc,
			      BTRFS_SC_BLOCK_SIZE - offset);
	btrfs_csum_final(crc, (char *)&crc);
	io_ctl->crcs[index] = crc;
}

static int io_ctl_check_crc(struct io_ctl *io_ctl, int index)
{
	u32 val;
	u32 crc = ~(u32)0;
	unsigned offset = 0;

	if (!io_ctl->check_crcs)
		return 0;

	if (index == 0) {
		offset = sizeof(u32) * io_ctl->num_blocks;
		/*
		 * The current page is full of CRCs, we have skipped it
		 * in the caller.
		 */
		BUG_ON(unlikely(BTRFS_SC_BLOCK_SIZE - offset < sizeof(u64)));
	}

	val = io_ctl->crcs[index];
	crc = btrfs_csum_data(io_ctl->root, io_ctl->orig + offset, crc,
			      BTRFS_SC_BLOCK_SIZE - offset);
	btrfs_csum_final(crc, (char *)&crc);
	if (val != crc) {
		printk_ratelimited(KERN_ERR "btrfs: csum mismatch on free "
				   "space cache\n");
		return -EIO;
	}

	return 0;
}

static int io_ctl_next_block(struct io_ctl *io_ctl, int clear)
{
	if (io_ctl->block_index >= io_ctl->num_blocks - 1)
		return -ENOSPC;

	if (!io_ctl->cur) {
		io_ctl_map_page(io_ctl);
		goto out;
	}

	io_ctl->block_index++;
	if (io_ctl->block_index % BLOCKS_PER_PAGE == 0) {
		io_ctl_unmap_page(io_ctl);
		io_ctl_map_page(io_ctl);
		goto out;
	}

	io_ctl->orig += BTRFS_SC_BLOCK_SIZE;
	io_ctl->cur = io_ctl->orig;
	io_ctl->size = BTRFS_SC_BLOCK_SIZE;
out:
	if (clear)
		memset(io_ctl->cur, 0, BTRFS_SC_BLOCK_SIZE);
	return 0;
}

static void io_ctl_set_generation(struct io_ctl *io_ctl, u64 generation)
{
	int ret;
	__le64 *val;

	ret = io_ctl_next_block(io_ctl, 1);
	BUG_ON(ret);	/* Logic error */
	/*
	 * Skip the csum areas.  If we don't check crcs then we just have a
	 * 64bit chunk at the front of the first block.
	 */
	if (io_ctl->check_crcs) {
		io_ctl->cur += (sizeof(u32) * io_ctl->num_blocks);
		io_ctl->size -= sizeof(u64) +
				(sizeof(u32) * io_ctl->num_blocks);
	} else {
		io_ctl->cur += sizeof(u64);
		io_ctl->size -= sizeof(u64) * 2;
	}
	/* The current block is full of CRCs */
	if (unlikely(io_ctl->size < 0)) {
		/*
		 * needn't calc CRC because it is a page in which
		 * there are only CRCs.
		 */
		ret = io_ctl_next_block(io_ctl, 1);
		BUG_ON(ret);	/* Logic error */
		io_ctl->size -= sizeof(u64);
	}

	val = io_ctl->cur;
	*val = cpu_to_le64(generation);
	io_ctl->cur += sizeof(u64);
}

static int io_ctl_check_generation(struct io_ctl *io_ctl, u64 generation)
{
	__le64 *gen;
	int ret;

	ret = io_ctl_next_block(io_ctl, 0);
	BUG_ON(ret);
	/*
	 * Skip the csum areas.  If we don't check crcs then we just have a
	 * 64bit chunk at the front of the first block.
	 */
	if (io_ctl->check_crcs) {
		io_ctl->cur += (sizeof(u32) * io_ctl->num_blocks);
		io_ctl->size -= sizeof(u64) +
				(sizeof(u32) * io_ctl->num_blocks);
	} else {
		io_ctl->cur += sizeof(u64);
		io_ctl->size -= sizeof(u64) * 2;
	}
	/* The current block is full of CRCs */
	if (unlikely(io_ctl->size < 0)) {
		/*
		 * skip checking CRC of the first block because there are
		 * only CRCs on it.
		 */
		ret = io_ctl_next_block(io_ctl, 0);
		BUG_ON(ret);
		io_ctl->size -= sizeof(u64);
	}

	ret = io_ctl_check_crc(io_ctl, io_ctl->block_index);
	if (ret)
		return ret;

	gen = io_ctl->cur;
	if (le64_to_cpu(*gen) != generation) {
		printk_ratelimited(KERN_ERR "btrfs: space cache generation "
				   "(%Lu) does not match inode (%Lu)\n", *gen,
				   generation);
		return -EIO;
	}
	io_ctl->cur += sizeof(u64);

	return 0;
}

static int io_ctl_add_entry(struct io_ctl *io_ctl, u64 offset, u64 bytes,
			    void *bitmap)
{
	int ret;
	struct btrfs_free_space_entry *entry;

	if (unlikely(io_ctl->size < sizeof(struct btrfs_free_space_entry))) {
		io_ctl_set_crc(io_ctl, io_ctl->block_index);
		/* get next block */
		ret = io_ctl_next_block(io_ctl, 1);
		if (ret)
			return ret;
	}

	entry = io_ctl->cur;
	entry->offset = cpu_to_le64(offset);
	entry->bytes = cpu_to_le64(bytes);
	entry->type = (bitmap) ? BTRFS_FREE_SPACE_BITMAP :
		BTRFS_FREE_SPACE_EXTENT;
	io_ctl->cur += sizeof(struct btrfs_free_space_entry);
	io_ctl->size -= sizeof(struct btrfs_free_space_entry);
	return 0;
}

static int io_ctl_add_bitmap(struct io_ctl *io_ctl, void *bitmap,
			     int bitmap_size)
{
	void *tmp;
	int need_clear = (bitmap_size < BTRFS_SC_BLOCK_SIZE);
	int bs = (bitmap_size < BTRFS_SC_BLOCK_SIZE ? bitmap_size :
						      BTRFS_SC_BLOCK_SIZE);
	int offset;
	int ret;

	BUG_ON((bitmap_size % bs) || (BTRFS_SC_BLOCK_SIZE % bs));

	if (unlikely(!IS_ALIGNED((unsigned long)io_ctl->cur, bs))) {
		tmp = io_ctl->cur;
		io_ctl->cur = PTR_ALIGN(tmp, bs);
		io_ctl->size -= io_ctl->cur - tmp;
	}

	for (offset = 0; offset < bitmap_size; offset += bs) {
		if (io_ctl->size < bs) {
			io_ctl_set_crc(io_ctl, io_ctl->block_index);
			/* get next block */
			ret = io_ctl_next_block(io_ctl, need_clear);
			if (ret)
				return ret;
		}

		memcpy(io_ctl->cur, bitmap + offset, bs);
		io_ctl->size -= bs;
		io_ctl->cur += bs;
	}
	return 0;
}

static void io_ctl_zero_remaining_pages(struct io_ctl *io_ctl)
{
	io_ctl_set_crc(io_ctl, io_ctl->block_index);

	while (io_ctl->block_index < io_ctl->num_blocks - 1) {
		io_ctl_next_block(io_ctl, 1);
		io_ctl_set_crc(io_ctl, io_ctl->block_index);
	}
}

static int io_ctl_read_entry(struct io_ctl *io_ctl,
			    struct btrfs_free_space *entry, u8 *type)
{
	struct btrfs_free_space_entry *e;
	int ret;

	if (unlikely(io_ctl->size < sizeof(struct btrfs_free_space_entry))) {
		ret = io_ctl_next_block(io_ctl, 0);
		if (ret)
			return ret;
		ret = io_ctl_check_crc(io_ctl, io_ctl->block_index);
		if (ret)
			return ret;
	}

	e = io_ctl->cur;
	entry->offset = le64_to_cpu(e->offset);
	entry->bytes = le64_to_cpu(e->bytes);
	*type = e->type;
	io_ctl->cur += sizeof(struct btrfs_free_space_entry);
	io_ctl->size -= sizeof(struct btrfs_free_space_entry);
	return 0;
}

static int io_ctl_read_bitmap(struct io_ctl *io_ctl,
			      struct btrfs_free_space *entry, int bitmap_size)
{
	void *tmp;
	int bs = (bitmap_size < BTRFS_SC_BLOCK_SIZE ? bitmap_size :
						      BTRFS_SC_BLOCK_SIZE);
	int offset;
	int ret;

	BUG_ON((bitmap_size % bs) || (BTRFS_SC_BLOCK_SIZE % bs));

	if (unlikely(!IS_ALIGNED((unsigned long)io_ctl->cur, bs))) {
		tmp = io_ctl->cur;
		io_ctl->cur = PTR_ALIGN(tmp, bs);
		io_ctl->size -= io_ctl->cur - tmp;
	}

	for (offset = 0; offset < bitmap_size; offset += bs) {
		if (io_ctl->size < bs) {
			ret = io_ctl_next_block(io_ctl, 0);
			if (ret)
				return ret;
			ret = io_ctl_check_crc(io_ctl, io_ctl->block_index);
			if (ret)
				return ret;
		}

		memcpy(entry->bitmap + offset, io_ctl->cur, bs);
		io_ctl->size -= bs;
		io_ctl->cur += bs;
	}
	return 0;
}

/*
 * Since we attach pinned extents after the fact we can have contiguous sections
 * of free space that are split up in entries.  This poses a problem with the
 * tree logging stuff since it could have allocated across what appears to be 2
 * entries since we would have merged the entries when adding the pinned extents
 * back to the free space cache.  So run through the space cache that we just
 * loaded and merge contiguous entries.  This will make the log replay stuff not
 * blow up and it will make for nicer allocator behavior.
 */
static void merge_space_tree(struct btrfs_free_space_ctl *ctl)
{
	struct btrfs_free_space *e, *prev = NULL;
	struct rb_node *n;

again:
	spin_lock(&ctl->tree_lock);
	n = rb_first(&ctl->extent_root);
	if (!n)
		goto out;

	prev = rb_entry(n, struct btrfs_free_space, node);
	for (n = rb_next(n); n; n = rb_next(n)) {
		e = rb_entry(n, struct btrfs_free_space, node);
		if (prev->offset + prev->bytes == e->offset) {
			__unlink_free_space(ctl, e);
			prev->bytes += e->bytes;
			kmem_cache_free(btrfs_free_space_cachep, e);
			n = &prev->node;
		} else {
			prev = e;
		}

		if (need_resched()) {
			spin_unlock(&ctl->tree_lock);
			cond_resched();
			goto again;
		}
	}
out:
	spin_unlock(&ctl->tree_lock);
}

int btrfs_load_cache(struct btrfs_root *root, struct inode *inode,
		     struct btrfs_free_space_ctl *ctl,
		     struct btrfs_path *path, u64 offset)
{
	struct btrfs_free_space_header *header;
	struct extent_buffer *leaf;
	struct io_ctl io_ctl;
	struct btrfs_key key;
	struct btrfs_free_space *e, *n;
	struct list_head bitmaps;
	u64 num_entries;
	u64 num_bitmaps;
	u64 generation;
	u8 type;
	int ret = 0;

	INIT_LIST_HEAD(&bitmaps);

	/* Nothing in the space cache, goodbye */
	if (!i_size_read(inode))
		return 0;

	key.objectid = BTRFS_FREE_SPACE_OBJECTID;
	key.offset = offset;
	key.type = 0;

	ret = btrfs_search_slot(NULL, root, &key, path, 0, 0);
	if (ret < 0)
		return 0;
	else if (ret > 0) {
		btrfs_release_path(path);
		return 0;
	}

	ret = -1;

	leaf = path->nodes[0];
	header = btrfs_item_ptr(leaf, path->slots[0],
				struct btrfs_free_space_header);
	num_entries = btrfs_free_space_entries(leaf, header);
	num_bitmaps = btrfs_free_space_bitmaps(leaf, header);
	generation = btrfs_free_space_generation(leaf, header);
	btrfs_release_path(path);

	if (BTRFS_I(inode)->generation != generation) {
		printk(KERN_ERR "btrfs: free space inode generation (%llu) did"
		       " not match free space cache generation (%llu)\n",
		       (unsigned long long)BTRFS_I(inode)->generation,
		       (unsigned long long)generation);
		return 0;
	}

	if (!num_entries)
		return 0;

	ret = io_ctl_init(&io_ctl, inode, root);
	if (ret)
		return ret;

	ret = readahead_cache(inode);
	if (ret)
		goto out;

	ret = io_ctl_prepare_pages(&io_ctl, inode, 1);
	if (ret)
		goto out;

	ret = io_ctl_check_generation(&io_ctl, generation);
	if (ret)
		goto free_cache;

	while (num_entries) {
		e = kmem_cache_zalloc(btrfs_free_space_cachep,
				      GFP_NOFS);
		if (!e)
			goto free_cache;

		ret = io_ctl_read_entry(&io_ctl, e, &type);
		if (ret) {
			kmem_cache_free(btrfs_free_space_cachep, e);
			goto free_cache;
		}

		if (!e->bytes) {
			kmem_cache_free(btrfs_free_space_cachep, e);
			goto free_cache;
		}

		if (type == BTRFS_FREE_SPACE_EXTENT) {
			/*
			 * Needn't acquire ->tree_lock because we are sure
			 * that only one thread can access the tree now.
			 *
			 * The same below.
			 */
			ret = link_free_space(ctl, e);
			if (ret) {
				printk(KERN_ERR "Duplicate entries in "
				       "free space cache, dumping\n");
				kmem_cache_free(btrfs_free_space_cachep, e);
				goto free_cache;
			}
		} else {
			BUG_ON(!num_bitmaps);
			num_bitmaps--;
			e->bitmap = kzalloc(BITMAP_SIZE, GFP_NOFS);
			if (!e->bitmap) {
				kmem_cache_free(
					btrfs_free_space_cachep, e);
				goto free_cache;
			}
			ret = link_free_space(ctl, e);
			ctl->total_bitmaps++;
			ctl->op->recalc_thresholds(ctl);
			if (ret) {
				printk(KERN_ERR "Duplicate entries in "
				       "free space cache, dumping\n");
				kmem_cache_free(btrfs_free_space_cachep, e);
				goto free_cache;
			}
			list_add_tail(&e->list, &bitmaps);
		}

		num_entries--;
	}

	io_ctl_unmap_page(&io_ctl);

	/*
	 * We add the bitmaps at the end of the entries in order that
	 * the bitmap entries are added to the cache.
	 */
	list_for_each_entry_safe(e, n, &bitmaps, list) {
		list_del_init(&e->list);
		ret = io_ctl_read_bitmap(&io_ctl, e, BITMAP_SIZE);
		if (ret)
			goto free_cache;
	}

	io_ctl_drop_pages(&io_ctl);
	merge_space_tree(ctl);
	ret = 1;
out:
	io_ctl_free(&io_ctl);
	return ret;
free_cache:
	io_ctl_drop_pages(&io_ctl);
	__btrfs_remove_free_space_cache(ctl);
	goto out;
}

int btrfs_load_free_space_cache(struct btrfs_fs_info *fs_info,
				struct btrfs_block_group_cache *block_group)
{
	struct btrfs_free_space_ctl *ctl = block_group->free_space_ctl;
	struct btrfs_root *root = fs_info->tree_root;
	struct inode *inode;
	struct btrfs_path *path;
	int ret = 0;
	bool matched;
	u64 used = btrfs_block_group_used(&block_group->item);

	/*
	 * If this block group has been marked to be cleared for one reason or
	 * another then we can't trust the on disk cache, so just return.
	 */
	spin_lock(&block_group->lock);
	if (block_group->disk_cache_state != BTRFS_DC_WRITTEN) {
		spin_unlock(&block_group->lock);
		return 0;
	}
	spin_unlock(&block_group->lock);

	path = btrfs_alloc_path();
	if (!path)
		return 0;
	path->search_commit_root = 1;
	path->skip_locking = 1;

	inode = btrfs_lookup_free_space_inode(root, block_group, path);
	if (IS_ERR(inode)) {
		btrfs_free_path(path);
		return 0;
	}

	/* We may have converted the inode and made the cache invalid. */
	spin_lock(&block_group->lock);
	if (block_group->disk_cache_state != BTRFS_DC_WRITTEN) {
		spin_unlock(&block_group->lock);
		btrfs_free_path(path);
		goto out;
	}
	spin_unlock(&block_group->lock);

	ret = btrfs_load_cache(fs_info->tree_root, inode, ctl,
			       path, block_group->key.objectid);
	btrfs_free_path(path);
	if (ret <= 0)
		goto out;

	spin_lock(&ctl->tree_lock);
	matched = (ctl->free_space == (block_group->key.offset - used -
				       block_group->bytes_super));
	spin_unlock(&ctl->tree_lock);

	if (!matched) {
		__btrfs_remove_free_space_cache(ctl);
		printk(KERN_ERR "block group %llu has an wrong amount of free "
		       "space\n", block_group->key.objectid);
		ret = -1;
	}
out:
	if (ret < 0) {
		/* This cache is bogus, make sure it gets cleared */
		spin_lock(&block_group->lock);
		block_group->disk_cache_state = BTRFS_DC_CLEAR;
		spin_unlock(&block_group->lock);
		ret = 0;

		printk(KERN_ERR "btrfs: failed to load free space cache "
		       "for block group %llu\n", block_group->key.objectid);
	}

	iput(inode);
	return ret;
}

static struct rb_root *
__btrfs_free_space_select_root(struct btrfs_free_space_ctl *ctl,
			       struct btrfs_block_group_cache *block_group,
			       struct btrfs_free_space_iter *iter)
{
	struct rb_root *root;
	struct btrfs_free_cluster *cluster;

	switch (iter->type) {
	case BTRFS_FREE_SPACE_EXTENT_ROOT:
		root = &ctl->extent_root;
		break;
	case BTRFS_FREE_SPACE_BITMAP_ROOT:
		root = &ctl->bitmap_root;
		break;
	case BTRFS_FREE_SPACE_CLUSTER_ROOT:
		if (!block_group ||
		    list_empty(&block_group->cluster_list)) {
			root = NULL;
			break;
		}

		cluster = iter->cur_cluster;
		if (!cluster) {
			cluster = list_entry(block_group->cluster_list.next,
					     struct btrfs_free_cluster,
					     block_group_list);
		} else if (!list_is_last(&cluster->block_group_list,
					 &block_group->cluster_list)) {
			cluster = list_entry(cluster->block_group_list.next,
					     struct btrfs_free_cluster,
					     block_group_list);
		} else {
			cluster = NULL;
		}

		iter->cur_cluster = cluster;
		if (iter->cur_cluster)
			root = &iter->cur_cluster->root;
		else
			root = NULL;
		break;
	default:
		root = NULL;
		break;
	}

	return root;
}

static void
__btrfs_free_space_iter_start(struct btrfs_free_space_ctl *ctl,
			      struct btrfs_block_group_cache *block_group,
			      struct btrfs_free_space_iter *iter)
{
	iter->type = BTRFS_FREE_SPACE_EXTENT_ROOT;
	iter->space_info = NULL;
	iter->cur_cluster = NULL;
}

static struct btrfs_free_space *
__btrfs_free_space_iter_next(struct btrfs_free_space_ctl *ctl,
			     struct btrfs_block_group_cache *block_group,
			     struct btrfs_free_space_iter *iter)
{
	struct btrfs_free_space *free_space;
	struct rb_node *node;
	struct rb_root *root;

	if (iter->space_info) {
		node = rb_next(&iter->space_info->node);
	} else {
		root = __btrfs_free_space_select_root(ctl, block_group, iter);
		if (root)
			node = rb_first(root);
		else
			node = NULL;
	}

	if (!node) {
again:
		/*
		 * Though we just have one cluster in the block group now,
		 * we may introduce more clusters in the future. So the
		 * iteration of the cluster is different with the others,
		 * we need go through all the clusters.
		 */
		if (iter->type != BTRFS_FREE_SPACE_CLUSTER_ROOT)
			iter->type++;
		root = __btrfs_free_space_select_root(ctl, block_group, iter);
		if (root) {
			node = rb_first(root);
			if (!node)
				goto again;
		} else {
			node = NULL;
		}
	}

	if (node)
		free_space = rb_entry(node, struct btrfs_free_space,
				      node);
	else
		free_space = NULL;
	iter->space_info = free_space;

	return free_space;
}

/*
 * This is empty function which is used to make the logical
 * more readable.
 */
static inline void __btrfs_free_space_iter_end(void)
{
}

/**
 * btrfs_write_out_cache - write out cached info to an inode
 * @root - the root the inode belongs to
 * @ctl - the free space cache we are going to write out
 * @block_group - the block_group for this cache if it belongs to a block_group
 * @trans - the trans handle
 * @path - the path to use
 * @offset - the offset for the key we'll insert
 *
 * This function writes out a free space cache struct to disk for quick recovery
 * on mount.  This will return 0 if it was successfull in writing the cache out,
 * and -1 if it was not.
 */
int btrfs_write_out_cache(struct btrfs_root *root, struct inode *inode,
			  struct btrfs_free_space_ctl *ctl,
			  struct btrfs_block_group_cache *block_group,
			  struct btrfs_trans_handle *trans,
			  struct btrfs_path *path, u64 offset)
{
	struct btrfs_free_space_header *header;
	struct extent_buffer *leaf;
	struct list_head *pos, *n;
	struct extent_state *cached_state = NULL;
	struct extent_io_tree *unpin = NULL;
	struct btrfs_free_space *e;
	struct btrfs_free_space_iter iter;
	struct io_ctl io_ctl;
	struct list_head bitmap_list;
	struct btrfs_key key;
	u64 start, extent_start, extent_end, len;
	int entries = 0;
	int bitmaps = 0;
	int ret;
	int err = -1;

	INIT_LIST_HEAD(&bitmap_list);

	if (!i_size_read(inode))
		return -1;

	ret = io_ctl_init(&io_ctl, inode, root);
	if (ret)
		return -1;

	/* Lock all pages first so we can lock the extent safely. */
	io_ctl_prepare_pages(&io_ctl, inode, 0);

	lock_extent_bits(&BTRFS_I(inode)->io_tree, 0, i_size_read(inode) - 1,
			 0, &cached_state);

	/* Make sure we can fit our crcs into the first page */
	if (io_ctl.check_crcs &&
	    (io_ctl.num_blocks * sizeof(u32)) >= BTRFS_SC_BLOCK_SIZE) {
		WARN_ON(1);
		goto out_nospc;
	}

	io_ctl_set_generation(&io_ctl, trans->transid);

	/* Write out the extent entries */
	__btrfs_free_space_iter_start(ctl, block_group, &iter);
	while ((e = __btrfs_free_space_iter_next(ctl, block_group, &iter))) {
		entries++;
		ret = io_ctl_add_entry(&io_ctl, e->offset, e->bytes,
				       e->bitmap);
		if (ret) {
			__btrfs_free_space_iter_end();
			goto out_nospc;
		}

		if (e->bitmap) {
			list_add_tail(&e->list, &bitmap_list);
			bitmaps++;
		}
	}
	__btrfs_free_space_iter_end();

	/*
	 * We want to add any pinned extents to our free space cache
	 * so we don't leak the space
	 */

	/*
	 * We shouldn't have switched the pinned extents yet so this is the
	 * right one
	 */
	unpin = root->fs_info->pinned_extents;

	if (block_group)
		start = block_group->key.objectid;

	while (block_group && (start < block_group->key.objectid +
			       block_group->key.offset)) {
		ret = find_first_extent_bit(unpin, start,
					    &extent_start, &extent_end,
					    EXTENT_DIRTY, NULL);
		if (ret) {
			ret = 0;
			break;
		}

		/* This pinned extent is out of our range */
		if (extent_start >= block_group->key.objectid +
		    block_group->key.offset)
			break;

		extent_start = max(extent_start, start);
		extent_end = min(block_group->key.objectid +
				 block_group->key.offset, extent_end + 1);
		len = extent_end - extent_start;

		entries++;
		ret = io_ctl_add_entry(&io_ctl, extent_start, len, NULL);
		if (ret)
			goto out_nospc;

		start = extent_end;
	}

	/* Write out the bitmaps */
	list_for_each_safe(pos, n, &bitmap_list) {
		struct btrfs_free_space *entry =
			list_entry(pos, struct btrfs_free_space, list);

		ret = io_ctl_add_bitmap(&io_ctl, entry->bitmap, BITMAP_SIZE);
		if (ret)
			goto out_nospc;
		list_del_init(&entry->list);
	}

	/* Zero out the rest of the pages just to make sure */
	io_ctl_zero_remaining_pages(&io_ctl);

	ret = btrfs_dirty_pages(root, inode, io_ctl.pages, io_ctl.num_pages,
				0, i_size_read(inode), &cached_state);
	io_ctl_drop_pages(&io_ctl);
	unlock_extent_cached(&BTRFS_I(inode)->io_tree, 0,
			     i_size_read(inode) - 1, &cached_state, GFP_NOFS);

	if (ret)
		goto out;


	btrfs_wait_ordered_range(inode, 0, (u64)-1);

	key.objectid = BTRFS_FREE_SPACE_OBJECTID;
	key.offset = offset;
	key.type = 0;

	ret = btrfs_search_slot(trans, root, &key, path, 0, 1);
	if (ret < 0) {
		clear_extent_bit(&BTRFS_I(inode)->io_tree, 0, inode->i_size - 1,
				 EXTENT_DIRTY | EXTENT_DELALLOC, 0, 0, NULL,
				 GFP_NOFS);
		goto out;
	}
	leaf = path->nodes[0];
	if (ret > 0) {
		struct btrfs_key found_key;
		BUG_ON(!path->slots[0]);
		path->slots[0]--;
		btrfs_item_key_to_cpu(leaf, &found_key, path->slots[0]);
		if (found_key.objectid != BTRFS_FREE_SPACE_OBJECTID ||
		    found_key.offset != offset) {
			clear_extent_bit(&BTRFS_I(inode)->io_tree, 0,
					 inode->i_size - 1,
					 EXTENT_DIRTY | EXTENT_DELALLOC, 0, 0,
					 NULL, GFP_NOFS);
			btrfs_release_path(path);
			goto out;
		}
	}

	BTRFS_I(inode)->generation = trans->transid;
	header = btrfs_item_ptr(leaf, path->slots[0],
				struct btrfs_free_space_header);
	btrfs_set_free_space_entries(leaf, header, entries);
	btrfs_set_free_space_bitmaps(leaf, header, bitmaps);
	btrfs_set_free_space_generation(leaf, header, trans->transid);
	btrfs_mark_buffer_dirty(leaf);
	btrfs_release_path(path);

	err = 0;
out:
	io_ctl_free(&io_ctl);
	if (err) {
		invalidate_inode_pages2(inode->i_mapping);
		BTRFS_I(inode)->generation = 0;
	}
	btrfs_update_inode(trans, root, inode);
	return err;

out_nospc:
	list_for_each_safe(pos, n, &bitmap_list) {
		struct btrfs_free_space *entry =
			list_entry(pos, struct btrfs_free_space, list);
		list_del_init(&entry->list);
	}
	io_ctl_drop_pages(&io_ctl);
	unlock_extent_cached(&BTRFS_I(inode)->io_tree, 0,
			     i_size_read(inode) - 1, &cached_state, GFP_NOFS);
	goto out;
}

int btrfs_write_out_free_space_cache(struct btrfs_root *root,
				     struct btrfs_trans_handle *trans,
				     struct btrfs_block_group_cache *bg,
				     struct btrfs_path *path)
{
	struct btrfs_free_space_ctl *ctl = bg->free_space_ctl;
	struct inode *inode;
	int ret = 0;

	root = root->fs_info->tree_root;

	spin_lock(&bg->lock);
	if (bg->disk_cache_state < BTRFS_DC_SETUP) {
		spin_unlock(&bg->lock);
		return 0;
	}
	spin_unlock(&bg->lock);

	inode = btrfs_lookup_free_space_inode(root, bg, path);
	if (IS_ERR(inode))
		return 0;

	ret = btrfs_write_out_cache(root, inode, ctl, bg, trans,
				    path, bg->key.objectid);
	if (ret) {
		spin_lock(&bg->lock);
		bg->disk_cache_state = BTRFS_DC_ERROR;
		spin_unlock(&bg->lock);
		ret = 0;
#ifdef DEBUG
		pr_err("btrfs: failed to write free space cache for block group %llu\n",
		       bg->key.objectid);
#endif
	}

	iput(inode);
	return ret;
}

static inline unsigned long offset_to_bit(u64 bitmap_start, int unit_shift,
					  u64 offset)
{
	BUG_ON(offset < bitmap_start);
	offset -= bitmap_start;
	return (unsigned long)(offset >> unit_shift);
}

static inline unsigned long bytes_to_bits(u64 bytes, int unit_shift)
{
	return (unsigned long)(bytes >> unit_shift);
}

static inline u64 offset_to_bitmap(struct btrfs_free_space_ctl *ctl,
				   u64 offset)
{
	u64 bitmap_start;

	bitmap_start = offset - ctl->start;
	bitmap_start = round_down(bitmap_start, BYTES_PER_BITMAP(ctl));
	bitmap_start += ctl->start;

	return bitmap_start;
}

static int __tree_insert(struct rb_root *root, u64 offset,
			 struct rb_node *node)
{
	struct rb_node **p;
	struct rb_node *parent = NULL;
	struct btrfs_free_space *info;

	p = &root->rb_node;
	while (*p) {
		parent = *p;
		info = rb_entry(parent, struct btrfs_free_space, node);

		if (offset < info->offset)
			p = &(*p)->rb_left;
		else if (offset > info->offset)
			p = &(*p)->rb_right;
		else
			return -EEXIST;
	}

	rb_link_node(node, parent, p);
	rb_insert_color(node, root);

	return 0;
}

static inline int tree_insert_offset(struct btrfs_free_space_ctl *ctl,
				     u64 offset, struct rb_node *node,
				     bool is_bitmap)
{
	struct rb_root *root;

	if (is_bitmap)
		root = &ctl->bitmap_root;
	else
		root = &ctl->extent_root;

	return __tree_insert(root, offset, node);
}

/*
 * searches the tree for the given offset.
 *
 * fuzzy - If this is set, then we are trying to make an allocation, and we just
 * want a section that has at least bytes size and comes at or after the given
 * offset.
 */
static struct btrfs_free_space *
tree_search_offset(struct btrfs_free_space_ctl *ctl,
		   u64 offset, bool bitmap, bool fuzzy)
{
	struct rb_node *n;
	struct btrfs_free_space *entry = NULL;

	WARN_ON(bitmap && offset != offset_to_bitmap(ctl, offset));

	if (bitmap)
		n = ctl->bitmap_root.rb_node;
	else
		n = ctl->extent_root.rb_node;

	/* find entry that is closest to the 'offset' */
	while (n) {
		entry = rb_entry(n, struct btrfs_free_space, node);
		if (offset < entry->offset)
			n = n->rb_left;
		else if (offset > entry->offset)
			n = n->rb_right;
		else
			return entry;
	}

	if (!entry)
		return NULL;

	if (bitmap) {
		/*
		 * The offset is the exact start offset of the bitmap, so
		 * it is impossible that the previous bitmap covers it.
		 */
		if (!fuzzy)
			return NULL;

		n = rb_next(&entry->node);
		if (!n)
			return NULL;
		entry = rb_entry(n, struct btrfs_free_space, node);
		return entry;
	} else {
		if (entry->offset < offset &&
		    entry->offset + entry->bytes > offset)
			return entry;
		/* the previous extent entry may cover the offset. */
		if (entry->offset > offset &&
		    (n = rb_prev(&entry->node))) {
			entry = rb_entry(n, struct btrfs_free_space, node);
			if (entry->offset + entry->bytes > offset)
				return entry;
		}

		if (!fuzzy)
			return NULL;

		if (entry->offset < offset) {
			n = rb_next(&entry->node);
			if (!n)
				return NULL;
			entry = rb_entry(n, struct btrfs_free_space, node);
			return entry;
		} else {
			return entry;
		}
	}
}

static inline void
__unlink_free_space(struct btrfs_free_space_ctl *ctl,
		    struct btrfs_free_space *info)
{
	if (info->bitmap)
		rb_erase(&info->node, &ctl->bitmap_root);
	else
		rb_erase(&info->node, &ctl->extent_root);
	ctl->free_extents--;
}

static void unlink_free_space(struct btrfs_free_space_ctl *ctl,
			      struct btrfs_free_space *info)
{
	__unlink_free_space(ctl, info);
	ctl->free_space -= info->bytes;
}

static int link_free_space(struct btrfs_free_space_ctl *ctl,
			   struct btrfs_free_space *info)
{
	int ret = 0;

	BUG_ON(!info->bitmap && !info->bytes);
	ret = tree_insert_offset(ctl, info->offset, &info->node,
				 (info->bitmap != NULL));
	if (ret)
		return ret;

	ctl->free_space += info->bytes;
	ctl->free_extents++;
	return ret;
}

static void recalculate_thresholds(struct btrfs_free_space_ctl *ctl)
{
	struct btrfs_block_group_cache *block_group = ctl->private;
	u64 max_bytes;
	u64 bitmap_bytes;
	u64 extent_bytes;
	u64 size = block_group->key.offset;
	int max_bitmaps;

	BUG_ON(!size);

	max_bitmaps = (int)DIV_ROUND_UP_SHIFT(size,
					      BYTES_PER_BITMAP_SHIFT(ctl));
	BUG_ON(ctl->total_bitmaps > max_bitmaps);
	/*
	 * The goal is to keep the total amount of memory used per 1gb of space
	 * at or below 32k, so we need to adjust how much memory we allow to be
	 * used by extent based free space tracking
	 */
	if (size < 1024 * 1024 * 1024)
		max_bytes = MAX_CACHE_BYTES_PER_GIG(ctl);
	else
		max_bytes = MAX_CACHE_BYTES_PER_GIG(ctl) *
			    DIV_ROUND_UP_SHIFT(size, 30);

	/*
	 * we want to account for 1 more bitmap than what we have so we can make
	 * sure we don't go over our overall goal of MAX_CACHE_BYTES_PER_GIG as
	 * we add more bitmaps.
	 */
	bitmap_bytes = (ctl->total_bitmaps + 1) * BITMAP_SIZE;

	if (bitmap_bytes >= max_bytes) {
		ctl->extents_thresh = 0;
		return;
	}

	/*
	 * we want the extent entry threshold to always be at most 1/2 the maxw
	 * bytes we can have, or whatever is less than that.
	 */
	extent_bytes = max_bytes - bitmap_bytes;
	extent_bytes = min_t(u64, extent_bytes, div64_u64(max_bytes, 2));

	ctl->extents_thresh =
		div64_u64(extent_bytes, (sizeof(struct btrfs_free_space)));
}

static inline void __bitmap_clear_bits(struct btrfs_free_space_ctl *ctl,
				       struct btrfs_free_space *info,
				       u64 offset, u64 bytes)
{
	unsigned long start, count;

	start = offset_to_bit(info->offset, ctl->unit_shift, offset);
	count = bytes_to_bits(bytes, ctl->unit_shift);
	BUG_ON(start + count > BITS_PER_BITMAP);

	bitmap_clear(info->bitmap, start, count);

	info->bytes -= bytes;
}

static void bitmap_clear_bits(struct btrfs_free_space_ctl *ctl,
			      struct btrfs_free_space *info, u64 offset,
			      u64 bytes)
{
	__bitmap_clear_bits(ctl, info, offset, bytes);
	ctl->free_space -= bytes;
}

static void bitmap_set_bits(struct btrfs_free_space_ctl *ctl,
			    struct btrfs_free_space *info, u64 offset,
			    u64 bytes)
{
	unsigned long start, count;

	start = offset_to_bit(info->offset, ctl->unit_shift, offset);
	count = bytes_to_bits(bytes, ctl->unit_shift);
	BUG_ON(start + count > BITS_PER_BITMAP);

	bitmap_set(info->bitmap, start, count);

	info->bytes += bytes;
	ctl->free_space += bytes;
}

static int search_bitmap(struct btrfs_free_space_ctl *ctl,
			 struct btrfs_free_space *bitmap_info, u64 *offset,
			 u64 *bytes)
{
	unsigned long found_bits = 0;
	unsigned long bits, i;
	unsigned long next_zero;

	i = offset_to_bit(bitmap_info->offset, ctl->unit_shift,
			  max_t(u64, *offset, bitmap_info->offset));
	bits = bytes_to_bits(*bytes, ctl->unit_shift);

	for_each_set_bit_from(i, bitmap_info->bitmap, BITS_PER_BITMAP) {
		next_zero = find_next_zero_bit(bitmap_info->bitmap,
					       BITS_PER_BITMAP, i);
		if ((next_zero - i) >= bits) {
			found_bits = next_zero - i;
			break;
		}
		i = next_zero;
	}

	if (found_bits) {
		*offset = ((u64)i << ctl->unit_shift) + bitmap_info->offset;
		*bytes = (u64)(found_bits) << ctl->unit_shift;
		return 0;
	}

	return -1;
}

static struct btrfs_free_space *
find_free_space(struct btrfs_free_space_ctl *ctl, u64 *offset, u64 *bytes,
		unsigned long align)
{
	struct btrfs_free_space *entry = NULL;
	struct rb_node *node;
	u64 tmp;
	u64 align_off;
	int ret;

	if (!RB_EMPTY_ROOT(&ctl->extent_root))
		entry = tree_search_offset(ctl, *offset, 0, 1);
again:
	if (!entry && !RB_EMPTY_ROOT(&ctl->bitmap_root))
		entry = tree_search_offset(ctl, offset_to_bitmap(ctl, *offset),
					   1, 1);
	if (!entry)
		return NULL;

	for (node = &entry->node; node; node = rb_next(node)) {
		entry = rb_entry(node, struct btrfs_free_space, node);
		if (entry->bytes < *bytes)
			continue;

		/* make sure the space returned is big enough
		 * to match our requested alignment
		 */
		if (*bytes >= align) {
			tmp = entry->offset - ctl->start;
			tmp = ALIGN(tmp, align) + ctl->start;
			align_off = tmp - entry->offset;
		} else {
			align_off = 0;
			tmp = entry->offset;
		}

		if (entry->bytes < *bytes + align_off)
			continue;

		if (entry->bitmap) {
			ret = search_bitmap(ctl, entry, &tmp, bytes);
			if (!ret) {
				*offset = tmp;
				return entry;
			}
			continue;
		}

		*offset = tmp;
		*bytes = entry->bytes - align_off;
		return entry;
	}

	if (!entry->bitmap) {
		entry = NULL;
		goto again;
	}

	return NULL;
}

static void add_new_bitmap(struct btrfs_free_space_ctl *ctl,
			   struct btrfs_free_space *info, u64 offset)
{
	info->offset = offset_to_bitmap(ctl, offset);
	info->bytes = 0;
	INIT_LIST_HEAD(&info->list);

	link_free_space(ctl, info);

	ctl->total_bitmaps++;
	ctl->op->recalc_thresholds(ctl);
}

static void free_bitmap(struct btrfs_free_space_ctl *ctl,
			struct btrfs_free_space *bitmap_info)
{
	unlink_free_space(ctl, bitmap_info);
	kfree(bitmap_info->bitmap);
	kmem_cache_free(btrfs_free_space_cachep, bitmap_info);
	ctl->total_bitmaps--;
	ctl->op->recalc_thresholds(ctl);
}

static noinline int remove_from_bitmap(struct btrfs_free_space_ctl *ctl,
			      struct btrfs_free_space *bitmap_info,
			      u64 *offset, u64 *bytes)
{
	u64 end;
	u64 search_start, search_bytes;
	int ret;

again:
	end = bitmap_info->offset + BYTES_PER_BITMAP(ctl) - 1;

	/*
	 * We need to search for bits in this bitmap.  We could only cover some
	 * of the extent in this bitmap thanks to how we add space, so we need
	 * to search for as much as it as we can and clear that amount, and then
	 * go searching for the next bit.
	 */
	search_start = *offset;
	search_bytes = ctl->unit;
	search_bytes = min(search_bytes, end - search_start + 1);
	ret = search_bitmap(ctl, bitmap_info, &search_start, &search_bytes);
	BUG_ON(ret < 0 || search_start != *offset);

	/* We may have found more bits than what we need */
	search_bytes = min(search_bytes, *bytes);

	/* Cannot clear past the end of the bitmap */
	search_bytes = min(search_bytes, end - search_start + 1);

	bitmap_clear_bits(ctl, bitmap_info, search_start, search_bytes);
	*offset += search_bytes;
	*bytes -= search_bytes;

	if (*bytes) {
		struct rb_node *next = rb_next(&bitmap_info->node);
		if (!bitmap_info->bytes)
			free_bitmap(ctl, bitmap_info);

		/*
		 * no entry after this bitmap, but we still have bytes to
		 * remove, so something has gone wrong.
		 */
		if (!next)
			return -EINVAL;

		bitmap_info = rb_entry(next, struct btrfs_free_space, node);

		/*
		 * if the next entry isn't a bitmap we need to return to let the
		 * extent stuff do its work.
		 */
		if (!bitmap_info->bitmap)
			return -EAGAIN;

		/*
		 * Ok the next item is a bitmap, but it may not actually hold
		 * the information for the rest of this free space stuff, so
		 * look for it, and if we don't find it return so we can try
		 * everything over again.
		 */
		search_start = *offset;
		search_bytes = ctl->unit;
		ret = search_bitmap(ctl, bitmap_info, &search_start,
				    &search_bytes);
		if (ret < 0 || search_start != *offset)
			return -EAGAIN;

		goto again;
	} else if (!bitmap_info->bytes)
		free_bitmap(ctl, bitmap_info);

	return 0;
}

static u64 add_bytes_to_bitmap(struct btrfs_free_space_ctl *ctl,
			       struct btrfs_free_space *info, u64 offset,
			       u64 bytes)
{
	u64 bytes_to_set = 0;
	u64 end;

	end = info->offset + (u64)(BYTES_PER_BITMAP(ctl));

	bytes_to_set = min(end - offset, bytes);

	bitmap_set_bits(ctl, info, offset, bytes_to_set);

	return bytes_to_set;

}

static bool use_bitmap(struct btrfs_free_space_ctl *ctl,
		      struct btrfs_free_space *info)
{
	struct btrfs_block_group_cache *block_group = ctl->private;

	/*
	 * If we are below the extents threshold then we can add this as an
	 * extent, and don't have to deal with the bitmap
	 */
	if (ctl->free_extents < ctl->extents_thresh) {
		/*
		 * If this block group has some small extents we don't want to
		 * use up all of our free slots in the cache with them, we want
		 * to reserve them to larger extents, however if we have plent
		 * of cache left then go ahead an dadd them, no sense in adding
		 * the overhead of a bitmap if we don't have to.
		 */
		if (info->bytes <= block_group->sectorsize * 4) {
			if (ctl->free_extents * 2 <= ctl->extents_thresh)
				return false;
		} else {
			return false;
		}
	}

	/*
	 * The original block groups from mkfs can be really small, like 8
	 * megabytes, so don't bother with a bitmap for those entries.  However
	 * some block groups can be smaller than what a bitmap would cover but
	 * are still large enough that they could overflow the 32k memory limit,
	 * so allow those block groups to still be allowed to have a bitmap
	 * entry.
	 */
	if (block_group->key.offset < (BYTES_PER_BITMAP(ctl) >> 1))
		return false;

	return true;
}

static struct btrfs_free_space_op free_space_op = {
	.recalc_thresholds	= recalculate_thresholds,
	.use_bitmap		= use_bitmap,
};

static int insert_into_bitmap(struct btrfs_free_space_ctl *ctl,
			      struct btrfs_free_space *info)
{
	struct btrfs_free_space *bitmap_info;
	struct btrfs_block_group_cache *block_group = NULL;
	int added = 0;
	u64 bytes, offset, bytes_added;
	int ret;

	bytes = info->bytes;
	offset = info->offset;

	if (!ctl->op->use_bitmap(ctl, info))
		return 0;

	if (ctl->op == &free_space_op)
		block_group = ctl->private;
again:
	/*
	 * Since we link bitmaps right into the cluster we need to see if we
	 * have a cluster here, and if so and it has our bitmap we need to add
	 * the free space to that bitmap.
	 */
	if (block_group && !list_empty(&block_group->cluster_list)) {
		struct btrfs_free_cluster *cluster;
		struct rb_node *node;
		struct btrfs_free_space *entry;

		cluster = list_entry(block_group->cluster_list.next,
				     struct btrfs_free_cluster,
				     block_group_list);
		spin_lock(&cluster->lock);
		node = rb_first(&cluster->root);
		if (!node) {
			spin_unlock(&cluster->lock);
			goto no_cluster_bitmap;
		}

		entry = rb_entry(node, struct btrfs_free_space, node);
		if (!entry->bitmap) {
			spin_unlock(&cluster->lock);
			goto no_cluster_bitmap;
		}

		if (entry->offset == offset_to_bitmap(ctl, offset)) {
			bytes_added = add_bytes_to_bitmap(ctl, entry,
							  offset, bytes);
			bytes -= bytes_added;
			offset += bytes_added;
		}
		spin_unlock(&cluster->lock);
		if (!bytes) {
			ret = 1;
			goto out;
		}
	}

no_cluster_bitmap:
	bitmap_info = tree_search_offset(ctl, offset_to_bitmap(ctl, offset),
					 1, 0);
	if (!bitmap_info) {
		BUG_ON(added);
		goto new_bitmap;
	}

	bytes_added = add_bytes_to_bitmap(ctl, bitmap_info, offset, bytes);
	bytes -= bytes_added;
	offset += bytes_added;
	added = 0;

	if (!bytes) {
		ret = 1;
		goto out;
	} else
		goto again;

new_bitmap:
	if (info && info->bitmap) {
		add_new_bitmap(ctl, info, offset);
		added = 1;
		info = NULL;
		goto again;
	} else {
		spin_unlock(&ctl->tree_lock);

		/* no pre-allocated info, allocate a new one */
		if (!info) {
			info = kmem_cache_zalloc(btrfs_free_space_cachep,
						 GFP_NOFS);
			if (!info) {
				spin_lock(&ctl->tree_lock);
				ret = -ENOMEM;
				goto out;
			}
		}

		/* allocate the bitmap */
		info->bitmap = kzalloc(BITMAP_SIZE, GFP_NOFS);
		spin_lock(&ctl->tree_lock);
		if (!info->bitmap) {
			ret = -ENOMEM;
			goto out;
		}
		goto again;
	}

out:
	if (info) {
		if (info->bitmap)
			kfree(info->bitmap);
		kmem_cache_free(btrfs_free_space_cachep, info);
	}

	return ret;
}

static bool try_merge_free_space(struct btrfs_free_space_ctl *ctl,
				 u64 offset, u64 bytes, bool update_stat)
{
	struct btrfs_free_space *left_info;
	struct btrfs_free_space *right_info;
	struct rb_node *n;
	bool merged = false;

	/*
	 * try to find the left entry which is adjacent to the range we
	 * are adding.
	 */
	left_info = tree_search_offset(ctl, offset - 1, 0, 0);
	if (left_info) {
		if (update_stat)
			ctl->free_space += bytes;
		left_info->bytes += bytes;
		merged = true;
	}

	/* Deal with the right one if it exists. */
	if (left_info && (n = rb_next(&left_info->node))) {
		right_info = rb_entry(n, struct btrfs_free_space, node);
		if (right_info->offset != offset + bytes)
			right_info = NULL;
	} else {
		right_info = tree_search_offset(ctl, offset + bytes, 0, 0);
	}

	if (right_info) {
		/*
		 * If it is merged to the left one, we just merge the left
		 * one to the right one.
		 */
		if (merged) {
			offset = left_info->offset;
			bytes = left_info->bytes;
			__unlink_free_space(ctl, left_info);
			kmem_cache_free(btrfs_free_space_cachep, left_info);
		} else if (update_stat) {
			ctl->free_space += bytes;
		}
		right_info->offset = offset;
		right_info->bytes += bytes;
		merged = true;
	}

	return merged;
}

int __btrfs_add_free_space(struct btrfs_free_space_ctl *ctl,
			   u64 offset, u64 bytes)
{
	struct btrfs_free_space *info;
	int ret = 0;

	info = kmem_cache_zalloc(btrfs_free_space_cachep, GFP_NOFS);
	if (!info)
		return -ENOMEM;

	spin_lock(&ctl->tree_lock);
	if (try_merge_free_space(ctl, offset, bytes, true)) {
		kmem_cache_free(btrfs_free_space_cachep, info);
		goto out;
	}

	info->offset = offset;
	info->bytes = bytes;
	/*
	 * There was no extent directly to the left or right of this new
	 * extent then we know we're going to have to allocate a new extent, so
	 * before we do that see if we need to drop this into a bitmap
	 */
	ret = insert_into_bitmap(ctl, info);
	if (ret < 0) {
		goto out;
	} else if (ret) {
		ret = 0;
		goto out;
	}
	ret = link_free_space(ctl, info);
	if (ret)
		kmem_cache_free(btrfs_free_space_cachep, info);
out:
	spin_unlock(&ctl->tree_lock);

	if (ret) {
		printk(KERN_CRIT "btrfs: unable to add free space :%d\n", ret);
		BUG_ON(ret == -EEXIST);
	}

	return ret;
}

int btrfs_remove_free_space(struct btrfs_block_group_cache *block_group,
			    u64 offset, u64 bytes)
{
	struct btrfs_free_space_ctl *ctl = block_group->free_space_ctl;
	struct btrfs_free_space *info;
	int ret;
	bool re_search = false;

	spin_lock(&ctl->tree_lock);
again:
	ret = 0;
	if (!bytes)
		goto out_lock;

	info = tree_search_offset(ctl, offset, 0, 0);
	if (!info) {
		/*
		 * oops didn't find an extent that matched the space we wanted
		 * to remove, look for a bitmap instead
		 */
		info = tree_search_offset(ctl, offset_to_bitmap(ctl, offset),
					  1, 0);
		if (!info) {
			/*
			 * If we found a partial bit of our free space in a
			 * bitmap but then couldn't find the other part this may
			 * be a problem, so WARN about it.
			 */
			WARN_ON(re_search);
			goto out_lock;
		}
	}

	re_search = false;
	if (!info->bitmap) {
		if (offset == info->offset) {
			u64 to_free = min(bytes, info->bytes);

			info->bytes -= to_free;
			info->offset += to_free;
			ctl->free_space -= to_free;
			if (!info->bytes) {
				__unlink_free_space(ctl, info);
				kmem_cache_free(btrfs_free_space_cachep, info);
			}

			offset += to_free;
			bytes -= to_free;
			goto again;
		} else {
			u64 old_end = info->bytes + info->offset;

			info->bytes = offset - info->offset;
			ctl->free_space -= old_end - offset;

			/* Not enough bytes in this entry to satisfy us */
			if (old_end < offset + bytes) {
				bytes -= old_end - offset;
				offset = old_end;
				goto again;
			} else if (old_end == offset + bytes) {
				/* all done */
				goto out_lock;
			}
			spin_unlock(&ctl->tree_lock);

			ret = btrfs_add_free_space(block_group, offset + bytes,
						   old_end - (offset + bytes));
			WARN_ON(ret);
			goto out;
		}
	}

	ret = remove_from_bitmap(ctl, info, &offset, &bytes);
	if (ret == -EAGAIN) {
		re_search = true;
		goto again;
	}
	BUG_ON(ret); /* logic error */
out_lock:
	spin_unlock(&ctl->tree_lock);
out:
	return ret;
}

void btrfs_dump_free_space(struct btrfs_block_group_cache *block_group,
			   u64 bytes)
{
	struct btrfs_free_space_ctl *ctl = block_group->free_space_ctl;
	struct btrfs_free_space *info;
	struct rb_node *n;
	int count = 0;

	for (n = rb_first(&ctl->extent_root); n; n = rb_next(n)) {
		info = rb_entry(n, struct btrfs_free_space, node);
		if (info->bytes >= bytes && !block_group->ro)
			count++;
		printk(KERN_CRIT "entry offset %llu, bytes %llu, bitmap %s\n",
		       (unsigned long long)info->offset,
		       (unsigned long long)info->bytes,
		       "no");
	}
	for (n = rb_first(&ctl->bitmap_root); n; n = rb_next(n)) {
		info = rb_entry(n, struct btrfs_free_space, node);
		if (info->bytes >= bytes && !block_group->ro)
			count++;
		printk(KERN_CRIT "entry offset %llu, bytes %llu, bitmap %s\n",
		       (unsigned long long)info->offset,
		       (unsigned long long)info->bytes,
		       "yes");
	}
	printk(KERN_INFO "block group has cluster?: %s\n",
	       list_empty(&block_group->cluster_list) ? "no" : "yes");
	printk(KERN_INFO "%d blocks of free space at or bigger than bytes is"
	       "\n", count);
}

void btrfs_init_free_space_ctl(struct btrfs_block_group_cache *block_group)
{
	struct btrfs_free_space_ctl *ctl = block_group->free_space_ctl;

	spin_lock_init(&ctl->tree_lock);
	ctl->unit = block_group->sectorsize;
	ctl->unit_shift = ilog2(ctl->unit);
	ctl->start = block_group->key.objectid;
	ctl->private = block_group;
	ctl->op = &free_space_op;

	/*
	 * we only want to have 32k of ram per block group for keeping
	 * track of free space, and if we pass 1/2 of that we want to
	 * start converting things over to using bitmaps
	 */
	ctl->extents_thresh = ((1024 * 32) / 2) /
				sizeof(struct btrfs_free_space);
}

/*
 * for a given cluster, put all of its extents back into the free
 * space cache.  If the block group passed doesn't match the block group
 * pointed to by the cluster, someone else raced in and freed the
 * cluster already.  In that case, we just return without changing anything
 */
static int
__btrfs_return_cluster_to_free_space(
			     struct btrfs_block_group_cache *block_group,
			     struct btrfs_free_cluster *cluster)
{
	struct btrfs_free_space_ctl *ctl = block_group->free_space_ctl;
	struct btrfs_free_space *entry;
	struct rb_node *node;
	bool bitmap;

	spin_lock(&cluster->lock);
	if (cluster->block_group != block_group)
		goto out;

	cluster->block_group = NULL;
	cluster->window_start = 0;
	list_del_init(&cluster->block_group_list);

	node = rb_first(&cluster->root);
	while (node) {
		entry = rb_entry(node, struct btrfs_free_space, node);
		node = rb_next(&entry->node);
		rb_erase(&entry->node, &cluster->root);

		bitmap = (entry->bitmap != NULL);
		if (!bitmap &&
		    try_merge_free_space(ctl, entry->offset, entry->bytes,
					 false)) {
			kmem_cache_free(btrfs_free_space_cachep, entry);
			ctl->free_extents--;
			continue;
		}
		tree_insert_offset(ctl, entry->offset, &entry->node, bitmap);
	}
	cluster->root = RB_ROOT;
out:
	spin_unlock(&cluster->lock);
	btrfs_put_block_group(block_group);
	return 0;
}

void __btrfs_remove_free_space_cache_locked(struct btrfs_free_space_ctl *ctl)
{
	struct btrfs_free_space *info;
	struct rb_node *node;

	while ((node = rb_last(&ctl->extent_root)) != NULL) {
		info = rb_entry(node, struct btrfs_free_space, node);
		unlink_free_space(ctl, info);
		kmem_cache_free(btrfs_free_space_cachep, info);
		if (need_resched()) {
			spin_unlock(&ctl->tree_lock);
			cond_resched();
			spin_lock(&ctl->tree_lock);
		}
	}

	while ((node = rb_last(&ctl->bitmap_root)) != NULL) {
		info = rb_entry(node, struct btrfs_free_space, node);
		free_bitmap(ctl, info);
		if (need_resched()) {
			spin_unlock(&ctl->tree_lock);
			cond_resched();
			spin_lock(&ctl->tree_lock);
		}
	}
}

void __btrfs_remove_free_space_cache(struct btrfs_free_space_ctl *ctl)
{
	spin_lock(&ctl->tree_lock);
	__btrfs_remove_free_space_cache_locked(ctl);
	spin_unlock(&ctl->tree_lock);
}

void btrfs_remove_free_space_cache(struct btrfs_block_group_cache *block_group)
{
	struct btrfs_free_space_ctl *ctl = block_group->free_space_ctl;
	struct btrfs_free_cluster *cluster;

	spin_lock(&ctl->tree_lock);
	while (!list_empty(&block_group->cluster_list)) {
		cluster = list_first_entry(&block_group->cluster_list,
					   struct btrfs_free_cluster,
					   block_group_list);

		WARN_ON(cluster->block_group != block_group);
		__btrfs_return_cluster_to_free_space(block_group, cluster);
		if (need_resched()) {
			spin_unlock(&ctl->tree_lock);
			cond_resched();
			spin_lock(&ctl->tree_lock);
		}
	}
	__btrfs_remove_free_space_cache_locked(ctl);
	spin_unlock(&ctl->tree_lock);

}

u64 btrfs_find_space_for_alloc(struct btrfs_block_group_cache *block_group,
			       u64 offset, u64 bytes, u64 empty_size)
{
	struct btrfs_free_space_ctl *ctl = block_group->free_space_ctl;
	struct btrfs_free_space *entry = NULL;
	u64 bytes_search = bytes + empty_size;
	u64 ret = 0;
	u64 align_gap = 0;
	u64 align_gap_len = 0;

	spin_lock(&ctl->tree_lock);
	entry = find_free_space(ctl, &offset, &bytes_search,
				block_group->full_stripe_len);
	if (!entry)
		goto out;

	ret = offset;
	if (entry->bitmap) {
		bitmap_clear_bits(ctl, entry, offset, bytes);
		if (!entry->bytes)
			free_bitmap(ctl, entry);
	} else {
		align_gap_len = offset - entry->offset;
		align_gap = entry->offset;

		entry->offset = offset + bytes;
		WARN_ON(entry->bytes < bytes + align_gap_len);

		entry->bytes -= bytes + align_gap_len;
		ctl->free_space -= bytes + align_gap_len;
		if (!entry->bytes) {
			__unlink_free_space(ctl, entry);
			kmem_cache_free(btrfs_free_space_cachep, entry);
		}
	}
out:
	spin_unlock(&ctl->tree_lock);

	if (align_gap_len)
		__btrfs_add_free_space(ctl, align_gap, align_gap_len);
	return ret;
}

/*
 * given a cluster, put all of its extents back into the free space
 * cache.  If a block group is passed, this function will only free
 * a cluster that belongs to the passed block group.
 *
 * Otherwise, it'll get a reference on the block group pointed to by the
 * cluster and remove the cluster from it.
 */
int btrfs_return_cluster_to_free_space(
			       struct btrfs_block_group_cache *block_group,
			       struct btrfs_free_cluster *cluster)
{
	struct btrfs_free_space_ctl *ctl;
	int ret;

	/* first, get a safe pointer to the block group */
	spin_lock(&cluster->lock);
	if (!block_group) {
		block_group = cluster->block_group;
		if (!block_group) {
			spin_unlock(&cluster->lock);
			return 0;
		}
	} else if (cluster->block_group != block_group) {
		/* someone else has already freed it don't redo their work */
		spin_unlock(&cluster->lock);
		return 0;
	}
	atomic_inc(&block_group->count);
	spin_unlock(&cluster->lock);

	ctl = block_group->free_space_ctl;

	/* now return any extents the cluster had on it */
	spin_lock(&ctl->tree_lock);
	ret = __btrfs_return_cluster_to_free_space(block_group, cluster);
	spin_unlock(&ctl->tree_lock);

	/* finally drop our ref */
	btrfs_put_block_group(block_group);
	return ret;
}

static u64 btrfs_alloc_from_bitmap(struct btrfs_block_group_cache *block_group,
				   struct btrfs_free_cluster *cluster,
				   struct btrfs_free_space *entry,
				   u64 bytes, u64 min_start)
{
	struct btrfs_free_space_ctl *ctl = block_group->free_space_ctl;
	u64 search_start;
	u64 search_bytes;
	int err;

	search_start = min_start;
	search_bytes = bytes;

	err = search_bitmap(ctl, entry, &search_start, &search_bytes);
	if (err)
		return 0;

	__bitmap_clear_bits(ctl, entry, search_start, bytes);
	return search_start;
}

/*
 * given a cluster, try to allocate 'bytes' from it, returns 0
 * if it couldn't find anything suitably large, or a logical disk offset
 * if things worked out
 */
u64 btrfs_alloc_from_cluster(struct btrfs_block_group_cache *block_group,
			     struct btrfs_free_cluster *cluster, u64 bytes,
			     u64 min_start)
{
	struct btrfs_free_space_ctl *ctl = block_group->free_space_ctl;
	struct btrfs_free_space *entry = NULL;
	struct rb_node *node;
	u64 ret = 0;

	spin_lock(&cluster->lock);
	if (bytes > cluster->max_size)
		goto out;

	if (cluster->block_group != block_group)
		goto out;

	node = rb_first(&cluster->root);
	if (!node)
		goto out;

	entry = rb_entry(node, struct btrfs_free_space, node);
	while(1) {
		if (entry->bytes < bytes ||
		    (!entry->bitmap && entry->offset < min_start)) {
			node = rb_next(&entry->node);
			if (!node)
				break;
			entry = rb_entry(node, struct btrfs_free_space,
					 node);
			continue;
		}

		if (entry->bitmap) {
			ret = btrfs_alloc_from_bitmap(block_group,
						      cluster, entry, bytes,
						      cluster->window_start);
			if (ret == 0) {
				node = rb_next(&entry->node);
				if (!node)
					break;
				entry = rb_entry(node, struct btrfs_free_space,
						 node);
				continue;
			}
			if (ret == cluster->window_start)
				cluster->window_start += bytes;
		} else {
			ret = entry->offset;

			entry->offset += bytes;
			entry->bytes -= bytes;
		}

		if (entry->bytes == 0)
			rb_erase(&entry->node, &cluster->root);
		break;
	}
out:
	spin_unlock(&cluster->lock);

	if (!ret)
		return 0;

	spin_lock(&ctl->tree_lock);
	ctl->free_space -= bytes;
	if (entry->bytes == 0) {
		ctl->free_extents--;
		if (entry->bitmap) {
			kfree(entry->bitmap);
			ctl->total_bitmaps--;
			ctl->op->recalc_thresholds(ctl);
		}
		kmem_cache_free(btrfs_free_space_cachep, entry);
	}
	spin_unlock(&ctl->tree_lock);

	return ret;
}

static int btrfs_bitmap_cluster(struct btrfs_block_group_cache *block_group,
				struct btrfs_free_space *entry,
				struct btrfs_free_cluster *cluster,
				u64 offset, u64 bytes,
				u64 cont1_bytes, u64 min_bytes)
{
	struct btrfs_free_space_ctl *ctl = block_group->free_space_ctl;
	unsigned long next_zero;
	unsigned long i;
	unsigned long want_bits;
	unsigned long min_bits;
	unsigned long found_bits;
	unsigned long start = 0;
	unsigned long total_found = 0;
	int ret;

	i = offset_to_bit(entry->offset, ctl->unit_shift,
			  max_t(u64, offset, entry->offset));
	want_bits = bytes_to_bits(bytes, ctl->unit_shift);
	min_bits = bytes_to_bits(min_bytes, ctl->unit_shift);

again:
	found_bits = 0;
	for_each_set_bit_from(i, entry->bitmap, BITS_PER_BITMAP) {
		next_zero = find_next_zero_bit(entry->bitmap,
					       BITS_PER_BITMAP, i);
		if (next_zero - i >= min_bits) {
			found_bits = next_zero - i;
			break;
		}
		i = next_zero;
	}

	if (!found_bits)
		return -ENOSPC;

	if (!total_found) {
		start = i;
		cluster->max_size = 0;
	}

	total_found += found_bits;

	if (cluster->max_size < (found_bits << ctl->unit_shift))
		cluster->max_size = found_bits << ctl->unit_shift;

	if (total_found < want_bits || cluster->max_size < cont1_bytes) {
		i = next_zero + 1;
		goto again;
	}

	cluster->window_start = (start << ctl->unit_shift) + entry->offset;
	rb_erase(&entry->node, &ctl->bitmap_root);
	ret = __tree_insert(&cluster->root, entry->offset, &entry->node);
	BUG_ON(ret); /* -EEXIST; Logic error */

	trace_btrfs_setup_cluster(block_group, cluster,
				  total_found << ctl->unit_shift, 1);
	return 0;
}

/*
 * This searches the block group for just extents to fill the cluster with.
 * Try to find a cluster with at least bytes total bytes, at least one
 * extent of cont1_bytes, and other clusters of at least min_bytes.
 */
static noinline int
setup_cluster_no_bitmap(struct btrfs_block_group_cache *block_group,
			struct btrfs_free_cluster *cluster,
			u64 offset, u64 bytes, u64 cont1_bytes, u64 min_bytes)
{
	struct btrfs_free_space_ctl *ctl = block_group->free_space_ctl;
	struct btrfs_free_space *first = NULL;
	struct btrfs_free_space *entry = NULL;
	struct btrfs_free_space *last;
	struct rb_node *node;
	u64 window_start;
	u64 window_free;
	u64 max_extent;
	u64 total_size = 0;

	entry = tree_search_offset(ctl, offset, 0, 1);
	if (!entry)
		return -ENOSPC;

	while (entry->bytes < min_bytes) {
		node = rb_next(&entry->node);
		if (!node)
			return -ENOSPC;
		entry = rb_entry(node, struct btrfs_free_space, node);
	}

	window_start = entry->offset;
	window_free = entry->bytes;
	max_extent = entry->bytes;
	first = entry;
	last = entry;

	for (node = rb_next(&entry->node); node;
	     node = rb_next(&entry->node)) {
		entry = rb_entry(node, struct btrfs_free_space, node);

		if (entry->bytes < min_bytes)
			continue;

		last = entry;
		window_free += entry->bytes;
		if (entry->bytes > max_extent)
			max_extent = entry->bytes;
	}

	if (window_free < bytes || max_extent < cont1_bytes)
		return -ENOSPC;

	cluster->window_start = first->offset;

	node = &first->node;
	/*
	 * now we've found our entries, pull them out of the free space
	 * cache and put them into the cluster rbtree
	 */
	do {
		int ret;

		entry = rb_entry(node, struct btrfs_free_space, node);
		node = rb_next(&entry->node);
		if (entry->bytes < min_bytes)
			continue;

		rb_erase(&entry->node, &ctl->extent_root);
		ret = __tree_insert(&cluster->root, entry->offset,
				    &entry->node);
		total_size += entry->bytes;
		BUG_ON(ret); /* -EEXIST; Logic error */
	} while (node && entry != last);

	cluster->max_size = max_extent;
	trace_btrfs_setup_cluster(block_group, cluster, total_size, 0);
	return 0;
}

/*
 * This specifically looks for bitmaps that may work in the cluster, we assume
 * that we have already failed to find extents that will work.
 */
static noinline int
setup_cluster_bitmap(struct btrfs_block_group_cache *block_group,
		     struct btrfs_free_cluster *cluster,
		     u64 offset, u64 bytes, u64 cont1_bytes, u64 min_bytes)
{
	struct btrfs_free_space_ctl *ctl = block_group->free_space_ctl;
	struct btrfs_free_space *entry;
	struct rb_node *node;
	int ret = -ENOSPC;
	u64 bitmap_offset = offset_to_bitmap(ctl, offset);

	if (ctl->total_bitmaps == 0)
		return -ENOSPC;

	entry = tree_search_offset(ctl, bitmap_offset, 1, 1);
	if (!entry)
		return -ENOSPC;

	for (node = &entry->node; node; node = rb_next(&entry->node)) {
		entry = rb_entry(node, struct btrfs_free_space, node);
		if (entry->bytes < bytes)
			continue;
		ret = btrfs_bitmap_cluster(block_group, entry, cluster, offset,
					   bytes, cont1_bytes, min_bytes);
		if (!ret)
			return 0;
	}

	return -ENOSPC;
}

/*
 * here we try to find a cluster of blocks in a block group.  The goal
 * is to find at least bytes+empty_size.
 * We might not find them all in one contiguous area.
 *
 * returns zero and sets up cluster if things worked out, otherwise
 * it returns -enospc
 */
int btrfs_find_space_cluster(struct btrfs_trans_handle *trans,
			     struct btrfs_root *root,
			     struct btrfs_block_group_cache *block_group,
			     struct btrfs_free_cluster *cluster,
			     u64 offset, u64 bytes, u64 empty_size)
{
	struct btrfs_free_space_ctl *ctl = block_group->free_space_ctl;
	u64 min_bytes;
	u64 cont1_bytes;
	int ret;

	/*
	 * Choose the minimum extent size we'll require for this
	 * cluster.  For SSD_SPREAD, don't allow any fragmentation.
	 * For metadata, allow allocates with smaller extents.  For
	 * data, keep it dense.
	 */
	if (btrfs_test_opt(root, SSD_SPREAD)) {
		cont1_bytes = min_bytes = bytes + empty_size;
	} else if (block_group->flags & BTRFS_BLOCK_GROUP_METADATA) {
		cont1_bytes = bytes;
		min_bytes = block_group->sectorsize;
	} else {
		cont1_bytes = max(bytes, (bytes + empty_size) >> 2);
		min_bytes = block_group->sectorsize;
	}

	spin_lock(&ctl->tree_lock);

	/*
	 * If we know we don't have enough space to make a cluster don't even
	 * bother doing all the work to try and find one.
	 */
	if (ctl->free_space < bytes) {
		spin_unlock(&ctl->tree_lock);
		return -ENOSPC;
	}

	spin_lock(&cluster->lock);

	/* someone already found a cluster, hooray */
	if (cluster->block_group) {
		ret = 0;
		goto out;
	}

	trace_btrfs_find_cluster(block_group, offset, bytes, empty_size,
				 min_bytes);

	ret = setup_cluster_no_bitmap(block_group, cluster, offset,
				      bytes + empty_size,
				      cont1_bytes, min_bytes);
	if (ret)
		ret = setup_cluster_bitmap(block_group, cluster,
					   offset, bytes + empty_size,
					   cont1_bytes, min_bytes);
	if (!ret) {
		atomic_inc(&block_group->count);
		list_add_tail(&cluster->block_group_list,
			      &block_group->cluster_list);
		cluster->block_group = block_group;
	} else {
		trace_btrfs_failed_cluster_setup(block_group);
	}
out:
	spin_unlock(&cluster->lock);
	spin_unlock(&ctl->tree_lock);

	return ret;
}

/*
 * simple code to zero out a cluster
 */
void btrfs_init_free_cluster(struct btrfs_free_cluster *cluster)
{
	spin_lock_init(&cluster->lock);
	spin_lock_init(&cluster->refill_lock);
	cluster->root = RB_ROOT;
	cluster->max_size = 0;
	INIT_LIST_HEAD(&cluster->block_group_list);
	cluster->block_group = NULL;
}

static int do_trimming(struct btrfs_block_group_cache *block_group,
		       u64 *total_trimmed, u64 start, u64 bytes,
		       u64 reserved_start, u64 reserved_bytes)
{
	struct btrfs_space_info *space_info = block_group->space_info;
	struct btrfs_fs_info *fs_info = block_group->fs_info;
	int ret;
	int update = 0;
	u64 trimmed = 0;

	spin_lock(&space_info->lock);
	spin_lock(&block_group->lock);
	if (!block_group->ro) {
		block_group->reserved += reserved_bytes;
		space_info->bytes_reserved += reserved_bytes;
		update = 1;
	}
	spin_unlock(&block_group->lock);
	spin_unlock(&space_info->lock);

	ret = btrfs_error_discard_extent(fs_info->extent_root,
					 start, bytes, &trimmed);
	if (!ret)
		*total_trimmed += trimmed;

	btrfs_add_free_space(block_group, reserved_start, reserved_bytes);

	if (update) {
		spin_lock(&space_info->lock);
		spin_lock(&block_group->lock);
		if (block_group->ro)
			space_info->bytes_readonly += reserved_bytes;
		block_group->reserved -= reserved_bytes;
		space_info->bytes_reserved -= reserved_bytes;
		spin_unlock(&space_info->lock);
		spin_unlock(&block_group->lock);
	}

	return ret;
}

static int trim_no_bitmap(struct btrfs_block_group_cache *block_group,
			  u64 *total_trimmed, u64 start, u64 end, u64 minlen)
{
	struct btrfs_free_space_ctl *ctl = block_group->free_space_ctl;
	struct btrfs_free_space *entry;
	int ret = 0;
	u64 extent_start;
	u64 extent_bytes;
	u64 bytes;

	while (start < end) {
		spin_lock(&ctl->tree_lock);

		if (ctl->free_space < minlen) {
			spin_unlock(&ctl->tree_lock);
			break;
		}

		entry = tree_search_offset(ctl, start, 0, 1);
		if (!entry) {
			spin_unlock(&ctl->tree_lock);
			break;
		}

		if (entry->offset >= end) {
			spin_unlock(&ctl->tree_lock);
			break;
		}

		extent_start = entry->offset;
		extent_bytes = entry->bytes;
		start = max(start, extent_start);
		bytes = min(extent_start + extent_bytes, end) - start;
		if (bytes < minlen) {
			spin_unlock(&ctl->tree_lock);
			goto next;
		}

		unlink_free_space(ctl, entry);
		kmem_cache_free(btrfs_free_space_cachep, entry);

		spin_unlock(&ctl->tree_lock);

		ret = do_trimming(block_group, total_trimmed, start, bytes,
				  extent_start, extent_bytes);
		if (ret)
			break;
next:
		start += bytes;

		if (fatal_signal_pending(current)) {
			ret = -ERESTARTSYS;
			break;
		}

		cond_resched();
	}
	return ret;
}

static int trim_bitmaps(struct btrfs_block_group_cache *block_group,
			u64 *total_trimmed, u64 start, u64 end, u64 minlen)
{
	struct btrfs_free_space_ctl *ctl = block_group->free_space_ctl;
	struct btrfs_free_space *entry;
	int ret = 0;
	int ret2;
	u64 bytes;
	u64 offset = offset_to_bitmap(ctl, start);

	while (offset < end) {
		bool next_bitmap = false;

		spin_lock(&ctl->tree_lock);

		if (ctl->free_space < minlen) {
			spin_unlock(&ctl->tree_lock);
			break;
		}

		entry = tree_search_offset(ctl, offset, 1, 1);
		if (!entry) {
			spin_unlock(&ctl->tree_lock);
			break;
		}

		bytes = minlen;
		ret2 = search_bitmap(ctl, entry, &start, &bytes);
		if (ret2 || start >= end) {
			spin_unlock(&ctl->tree_lock);
			next_bitmap = true;
			goto next;
		}

		bytes = min(bytes, end - start);
		if (bytes < minlen) {
			spin_unlock(&ctl->tree_lock);
			goto next;
		}

		bitmap_clear_bits(ctl, entry, start, bytes);
		if (entry->bytes == 0)
			free_bitmap(ctl, entry);

		spin_unlock(&ctl->tree_lock);

		ret = do_trimming(block_group, total_trimmed, start, bytes,
				  start, bytes);
		if (ret)
			break;
next:
		if (next_bitmap) {
			offset += BYTES_PER_BITMAP(ctl);
		} else {
			start += bytes;
			if (start >= offset + BYTES_PER_BITMAP(ctl))
				offset += BYTES_PER_BITMAP(ctl);
		}

		if (fatal_signal_pending(current)) {
			ret = -ERESTARTSYS;
			break;
		}

		cond_resched();
	}

	return ret;
}

int btrfs_trim_block_group(struct btrfs_block_group_cache *block_group,
			   u64 *trimmed, u64 start, u64 end, u64 minlen)
{
	int ret;

	*trimmed = 0;

	ret = trim_no_bitmap(block_group, trimmed, start, end, minlen);
	if (ret)
		return ret;

	ret = trim_bitmaps(block_group, trimmed, start, end, minlen);

	return ret;
}

/*
 * Find the left-most item in the cache tree, and then return the
 * smallest unit in the item.
 */
u64 btrfs_alloc_unit_from_left(struct btrfs_free_space_ctl *ctl)
{
	struct btrfs_free_space *entry = NULL;
	u64 result = 0;

	spin_lock(&ctl->tree_lock);
	if (!RB_EMPTY_ROOT(&ctl->extent_root)) {
		entry = rb_entry(rb_first(&ctl->extent_root),
				 struct btrfs_free_space, node);
		result = entry->offset;

		entry->offset += ctl->unit;
		entry->bytes -= ctl->unit;
		ctl->free_space -= ctl->unit;
		if (!entry->bytes) {
			__unlink_free_space(ctl, entry);
			kmem_cache_free(btrfs_free_space_cachep, entry);
		}
	} else if (!RB_EMPTY_ROOT(&ctl->bitmap_root)){
		u64 offset = 0;
		u64 count = 1;
		int ret;

		entry = rb_entry(rb_first(&ctl->bitmap_root),
				 struct btrfs_free_space, node);
		ret = search_bitmap(ctl, entry, &offset, &count);
		/* Logic error; Should be empty if it can't find anything */
		BUG_ON(ret);

		result = offset;
		bitmap_clear_bits(ctl, entry, offset, 1);
		if (entry->bytes == 0)
			free_bitmap(ctl, entry);
	}
	spin_unlock(&ctl->tree_lock);

	return result;
}

