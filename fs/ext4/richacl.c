/*
 * Copyright IBM Corporation, 2010
 * Copyright (C) 2015  Red Hat, Inc.
 * Author: Aneesh Kumar K.V <aneesh.kumar@linux.vnet.ibm.com>,
 * 	   Andreas Gruenbacher <agruenba@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of version 2.1 of the GNU Lesser General Public License
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it would be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *
 */

#include <linux/kernel.h>
#include <linux/fs.h>
#include <linux/richacl_xattr.h>

#include "ext4.h"
#include "ext4_jbd2.h"
#include "xattr.h"
#include "acl.h"
#include "richacl.h"

struct richacl *
ext4_get_richacl(struct inode *inode)
{
	const int name_index = EXT4_XATTR_INDEX_RICHACL;
	void *value = NULL;
	struct richacl *acl = NULL;
	int retval;

	retval = ext4_xattr_get(inode, name_index, "", NULL, 0);
	if (retval > 0) {
		value = kmalloc(retval, GFP_NOFS);
		if (!value)
			return ERR_PTR(-ENOMEM);
		retval = ext4_xattr_get(inode, name_index, "", value, retval);
	}
	if (retval > 0)
		acl = richacl_from_xattr(&init_user_ns, value, retval, -EIO);
	else if (retval != -ENODATA && retval != -ENOSYS)
		acl = ERR_PTR(retval);
	kfree(value);

	return acl;
}

static int
__ext4_remove_richacl(handle_t *handle, struct inode *inode)
{
	const int name_index = EXT4_XATTR_INDEX_RICHACL;
	int retval;

	retval = ext4_xattr_set_handle(handle, inode, name_index, "",
				       NULL, 0, 0);
	if (!retval)
		set_cached_richacl(inode, NULL);
	return retval;
}

static int
__ext4_set_richacl(handle_t *handle, struct inode *inode, struct richacl *acl)
{
	const int name_index = EXT4_XATTR_INDEX_RICHACL;
	umode_t mode = inode->i_mode;
	int retval, size;
	void *value;

	/* Don't allow acls with unmapped identifiers. */
	if (richacl_has_unmapped_identifiers(acl))
		return -EINVAL;

	if (richacl_equiv_mode(acl, &mode) == 0) {
		inode->i_ctime = current_time(inode);
		inode->i_mode = mode;
		ext4_mark_inode_dirty(handle, inode);
		return __ext4_remove_richacl(handle, inode);
	}

	mode &= ~S_IRWXUGO;
	mode |= richacl_masks_to_mode(acl);

	size = richacl_xattr_size(acl);
	value = kmalloc(size, GFP_NOFS);
	if (!value)
		return -ENOMEM;
	richacl_to_xattr(&init_user_ns, acl, value, size);
	inode->i_mode = mode;
	retval = ext4_xattr_set_handle(handle, inode, name_index, "",
				       value, size, 0);
	kfree(value);
	if (retval)
		return retval;

	set_cached_richacl(inode, acl);

	return 0;
}

inline size_t ext4_richacl_size(struct richacl *acl){
	//this comes from richacl_clone()
	return sizeof(struct richacl) + acl->a_count * sizeof(struct richace)+acl->a_unmapped_size;
}

int
ext4_set_richacl(struct user_namespace *mnt_userns,struct inode *inode, struct richacl *acl)
{
	handle_t *handle;
	int error, credits;
	size_t acl_size = acl ? ext4_richacl_size(acl) : 0;
	int retval, retries = 0;

retry:
	error = ext4_xattr_set_credits(inode, acl_size, false /* is_create */,
				       &credits);
	if (error)
		return error;
	handle = ext4_journal_start(inode, EXT4_HT_XATTR,
				    credits);
	if (IS_ERR(handle))
		return PTR_ERR(handle);

	if (acl)
		retval = __ext4_set_richacl(handle, inode, acl);
	else
		retval = __ext4_remove_richacl(handle, inode);

	ext4_journal_stop(handle);
	if (retval == -ENOSPC && ext4_should_retry_alloc(inode->i_sb, &retries))
		goto retry;
	return retval;
}

int
ext4_init_richacl(handle_t *handle, struct inode *inode, struct inode *dir)
{
	struct richacl *acl = richacl_create(&inode->i_mode, dir);
	int error;

	error = PTR_ERR(acl);
	if (!IS_ERR_OR_NULL(acl)) {
		error = __ext4_set_richacl(handle, inode, acl);
		richacl_put(acl);
	}
	return error;
}
