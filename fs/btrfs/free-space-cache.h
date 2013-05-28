/*
 * Copyright (C) 2009 Oracle.  All rights reserved.
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

#ifndef __BTRFS_FREE_SPACE_CACHE
#define __BTRFS_FREE_SPACE_CACHE

#define BTRFS_SC_BLOCK_SIZE		4096
#define BTRFS_SC_BLOCK_SIZE_SHIFT	12

struct btrfs_free_space {
	struct rb_node node;
	u64 offset;
	u64 bytes;
	unsigned long *bitmap;
	struct list_head list;
};

struct btrfs_free_space_ctl {
	spinlock_t tree_lock;
	struct rb_root extent_root;
	struct rb_root bitmap_root;
	struct btrfs_free_space_op *op;
	void *private;
	u64 start;
	u64 free_space;
	int extents_thresh;
	int free_extents;
	int total_bitmaps;
	unsigned short unit;
	unsigned short unit_shift;
	int bitmap_size;
	int bits_per_bitmap;
	int bits_per_bitmap_shift;
};

enum btrfs_free_space_root_types {
	BTRFS_FREE_SPACE_EXTENT_ROOT,
	BTRFS_FREE_SPACE_BITMAP_ROOT,
	BTRFS_FREE_SPACE_CLUSTER_ROOT,
};

struct btrfs_free_cluster;

struct btrfs_free_space_iter {
	enum btrfs_free_space_root_types type;
	struct btrfs_free_space *space_info;
	struct btrfs_free_cluster *cur_cluster;
};

struct btrfs_free_space_op {
	void (*recalc_thresholds)(struct btrfs_free_space_ctl *ctl);
	bool (*use_bitmap)(struct btrfs_free_space_ctl *ctl, u64 bytes);
	u64 (*calc_cache_size)(struct btrfs_free_space_ctl *ctl);
	void *(*alloc_bitmap)(void);
	void (*free_bitmap)(struct btrfs_free_space *info);
	int (*search_bitmap)(struct btrfs_free_space_ctl *ctl,
			     struct btrfs_free_space *info,
			     u64 *start, u64 *bytes);
	int (*clear_bitmap)(struct btrfs_free_space_ctl *ctl,
			    struct btrfs_free_space *info,
			    u64 start, u64 bytes);
	int (*set_bitmap)(struct btrfs_free_space_ctl *ctl,
			    struct btrfs_free_space *info,
			    u64 start, u64 bytes);
};

struct btrfs_free_space_type {
	char *name;
	struct btrfs_free_space_ctl *(*alloc_cache_ctl)(void);
	void (*free_cache_ctl)(struct btrfs_free_space_ctl *ctl);
};

int btrfs_create_cache_inode(struct btrfs_root *root,
			     struct btrfs_trans_handle *trans,
			     struct btrfs_path *path, u64 ino, u64 offset);
struct inode *btrfs_lookup_cache_inode(struct btrfs_root *root,
				       struct btrfs_path *path,
				       u64 offset);
int btrfs_truncate_cache(struct btrfs_root *root,
			 struct btrfs_trans_handle *trans,
			 struct btrfs_path *path,
			 struct inode *inode);
int btrfs_load_cache(struct btrfs_root *root, struct inode *inode,
		     struct btrfs_free_space_ctl *ctl,
		     struct btrfs_path *path, u64 offset);
int btrfs_write_out_cache(struct btrfs_root *root, struct inode *inode,
			  struct btrfs_free_space_ctl *ctl,
			  struct btrfs_block_group_cache *block_group,
			  struct btrfs_trans_handle *trans,
			  struct btrfs_path *path, u64 offset);

struct inode *btrfs_lookup_free_space_inode(struct btrfs_root *root,
					    struct btrfs_block_group_cache *bg,
					    struct btrfs_path *path);
int btrfs_create_free_space_inode(struct btrfs_root *root,
				  struct btrfs_trans_handle *trans,
				  struct btrfs_block_group_cache *block_group,
				  struct btrfs_path *path);
int btrfs_load_free_space_cache(struct btrfs_fs_info *fs_info,
				struct btrfs_block_group_cache *block_group);
int btrfs_write_out_free_space_cache(struct btrfs_root *root,
				     struct btrfs_trans_handle *trans,
				     struct btrfs_block_group_cache *bg,
				     struct btrfs_path *path);

void btrfs_init_free_space_ctl(struct btrfs_block_group_cache *block_group);
int __btrfs_add_free_space(struct btrfs_free_space_ctl *ctl,
			   u64 bytenr, u64 size);
static inline int
btrfs_add_free_space(struct btrfs_block_group_cache *block_group,
		     u64 bytenr, u64 size)
{
	return __btrfs_add_free_space(block_group->free_space_ctl,
				      bytenr, size);
}
int btrfs_remove_free_space(struct btrfs_block_group_cache *block_group,
			    u64 bytenr, u64 size);
void __btrfs_remove_free_space_cache(struct btrfs_free_space_ctl *ctl);
void btrfs_remove_free_space_cache(struct btrfs_block_group_cache
				     *block_group);
u64 btrfs_find_space_for_alloc(struct btrfs_block_group_cache *block_group,
			       u64 offset, u64 bytes, u64 empty_size);
void btrfs_dump_free_space(struct btrfs_block_group_cache *block_group,
			   u64 bytes);
int btrfs_find_space_cluster(struct btrfs_trans_handle *trans,
			     struct btrfs_root *root,
			     struct btrfs_block_group_cache *block_group,
			     struct btrfs_free_cluster *cluster,
			     u64 offset, u64 bytes, u64 empty_size);
void btrfs_init_free_cluster(struct btrfs_free_cluster *cluster);
u64 btrfs_alloc_from_cluster(struct btrfs_block_group_cache *block_group,
			     struct btrfs_free_cluster *cluster, u64 bytes,
			     u64 min_start);
u64 btrfs_alloc_unit_from_left(struct btrfs_free_space_ctl *ctl);
int btrfs_return_cluster_to_free_space(
			       struct btrfs_block_group_cache *block_group,
			       struct btrfs_free_cluster *cluster);
int btrfs_trim_block_group(struct btrfs_block_group_cache *block_group,
			   u64 *trimmed, u64 start, u64 end, u64 minlen);
#endif
