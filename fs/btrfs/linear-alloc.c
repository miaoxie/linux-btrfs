
/*
 * Copyright (C) 2013 Fujitsu.  All rights reserved.
 * Written by Miao Xie <miaox@cn.fujitsu.com>
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
					       SPACE_CACHE_BLOCK_SIZE_SHIFT))
#define MAX_CACHE_BYTES_PER_GIG(ctl)	(1 << (30 - ctl->unit_shift -	\
					       BITS_PER_BITMAP_SHIFT +	\
					       SPACE_CACHE_BLOCK_SIZE_SHIFT))

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
 * smallest inode number in the item.
 *
 * Note: the returned inode number may not be the smallest one in
 * the tree, if the left-most item is a bitmap.
 */
u64 btrfs_find_ino_for_alloc(struct btrfs_root *fs_root)
{
	struct btrfs_free_space_ctl *ctl = fs_root->free_ino_ctl;
	struct btrfs_free_space *entry = NULL;
	u64 ino = 0;

	spin_lock(&ctl->tree_lock);
	if (!RB_EMPTY_ROOT(&ctl->extent_root)) {
		entry = rb_entry(rb_first(&ctl->extent_root),
				 struct btrfs_free_space, node);
		ino = entry->offset;

		entry->offset++;
		entry->bytes--;
		ctl->free_space--;
		if (!entry->bytes) {
			kmem_cache_free(btrfs_free_space_cachep, entry);
			__unlink_free_space(ctl, entry);
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

		ino = offset;
		bitmap_clear_bits(ctl, entry, offset, 1);
		if (entry->bytes == 0)
			free_bitmap(ctl, entry);
	}
	spin_unlock(&ctl->tree_lock);

	return ino;
}

struct inode *lookup_free_ino_inode(struct btrfs_root *root,
				    struct btrfs_path *path)
{
	struct inode *inode = NULL;

	spin_lock(&root->cache_lock);
	if (root->cache_inode)
		inode = igrab(root->cache_inode);
	spin_unlock(&root->cache_lock);
	if (inode)
		return inode;

	inode = __lookup_free_space_inode(root, path, 0);
	if (IS_ERR(inode))
		return inode;

	spin_lock(&root->cache_lock);
	if (!btrfs_fs_closing(root->fs_info))
		root->cache_inode = igrab(inode);
	spin_unlock(&root->cache_lock);

	return inode;
}

int create_free_ino_inode(struct btrfs_root *root,
			  struct btrfs_trans_handle *trans,
			  struct btrfs_path *path)
{
	return __create_free_space_inode(root, trans, path,
					 BTRFS_FREE_INO_OBJECTID, 0);
}

int load_free_ino_cache(struct btrfs_fs_info *fs_info, struct btrfs_root *root)
{
	struct btrfs_free_space_ctl *ctl = root->free_ino_ctl;
	struct btrfs_path *path;
	struct inode *inode;
	int ret = 0;
	u64 root_gen = btrfs_root_generation(&root->root_item);

	if (!btrfs_test_opt(root, INODE_MAP_CACHE))
		return 0;

	/*
	 * If we're unmounting then just return, since this does a search on the
	 * normal root and not the commit root and we could deadlock.
	 */
	if (btrfs_fs_closing(fs_info))
		return 0;

	path = btrfs_alloc_path();
	if (!path)
		return 0;

	inode = lookup_free_ino_inode(root, path);
	if (IS_ERR(inode))
		goto out;

	if (root_gen != BTRFS_I(inode)->generation)
		goto out_put;

	ret = __load_free_space_cache(root, inode, ctl, path, 0);

	if (ret < 0)
		printk(KERN_ERR "btrfs: failed to load free ino cache for "
		       "root %llu\n", root->root_key.objectid);
out_put:
	iput(inode);
out:
	btrfs_free_path(path);
	return ret;
}

int btrfs_write_out_ino_cache(struct btrfs_root *root,
			      struct btrfs_trans_handle *trans,
			      struct btrfs_path *path)
{
	struct btrfs_free_space_ctl *ctl = root->free_ino_ctl;
	struct inode *inode;
	int ret;

	if (!btrfs_test_opt(root, INODE_MAP_CACHE))
		return 0;

	inode = lookup_free_ino_inode(root, path);
	if (IS_ERR(inode))
		return 0;

	ret = __btrfs_write_out_cache(root, inode, ctl, NULL, trans, path, 0);
	if (ret) {
		btrfs_delalloc_release_metadata(inode, inode->i_size);
#ifdef DEBUG
		printk(KERN_ERR "btrfs: failed to write free ino cache "
		       "for root %llu\n", root->root_key.objectid);
#endif
	}

	iput(inode);
	return ret;
}
