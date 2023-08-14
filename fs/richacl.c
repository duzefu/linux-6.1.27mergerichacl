/*
 * Copyright (C) 2006, 2010  Novell, Inc.
 * Copyright (C) 2015  Red Hat, Inc.
 * Written by Andreas Gruenbacher <agruenba@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 */

#include <linux/sched.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/richacl.h>
#include <linux/mnt_idmapping.h>

void set_cached_richacl(struct inode *inode, struct richacl *acl)
{
	struct base_acl *old;

	old = xchg(&inode->i_acl, &richacl_get(acl)->a_base);
	if (!is_uncached_acl(old))
		base_acl_put(old);
}
EXPORT_SYMBOL_GPL(set_cached_richacl);

void forget_cached_richacl(struct inode *inode)
{
	__forget_cached_acl(&inode->i_acl);
}
EXPORT_SYMBOL_GPL(forget_cached_richacl);

struct richacl *get_richacl(struct inode *inode)
{
	struct base_acl *sentinel, *base_acl;
	struct richacl *acl;

	if (!IS_RICHACL(inode))
		return NULL;

	/*
	 * The sentinel is used to detect when another operation like
	 * set_cached_richacl() or forget_cached_richacl() races with
	 * get_richacl().
	 * It is guaranteed that is_uncached_acl(sentinel) is true.
	 */

	base_acl = __get_cached_acl(&inode->i_acl);
	if (!is_uncached_acl(base_acl))
		return richacl(base_acl);

	sentinel = uncached_acl_sentinel(current);

	/*
	 * If the ACL isn't being read yet, set our sentinel.  Otherwise, the
	 * current value of the ACL will not be ACL_NOT_CACHED and so our own
	 * sentinel will not be set; another task will update the cache.  We
	 * could wait for that other task to complete its job, but it's easier
	 * to just call ->get_acl to fetch the ACL ourself.  (This is going to
	 * be an unlikely race.)
	 */
	if (cmpxchg(&inode->i_acl, ACL_NOT_CACHED, sentinel) != ACL_NOT_CACHED)
		/* fall through */ ;

	/*
	 * Normally, the ACL returned by ->get_richacl will be cached.
	 * A filesystem can prevent that by calling
	 * forget_cached_richacl(inode) in ->get_richacl.
	 *
	 * If the filesystem doesn't have a ->get_richacl function at all,
	 * we'll just create the negative cache entry.
	 */
	if (!inode->i_op->get_richacl) {
		set_cached_richacl(inode, NULL);
		return NULL;
	}

	acl = inode->i_op->get_richacl(inode);
	if (IS_ERR(acl)) {
		/*
		 * Remove our sentinel so that we don't block future attempts
		 * to cache the ACL.
		 */
		cmpxchg(&inode->i_acl, sentinel, ACL_NOT_CACHED);
		return acl;
	}

	/*
	 * Cache the result, but only if our sentinel is still in place.
	 */
	richacl_get(acl);
	if (unlikely(cmpxchg(&inode->i_acl, sentinel, &acl->a_base) != sentinel))
		richacl_put(acl);
	return acl;
}
EXPORT_SYMBOL_GPL(get_richacl);

/**
 * __richacl_alloc  -  allocate a richacl
 * @count:	number of entries
 * @unmapped_size:	size to reserve for unmapped identifiers
 */
struct richacl *
__richacl_alloc(unsigned int count, size_t unmapped_size, gfp_t gfp)
{
	size_t size = sizeof(struct richacl) + count * sizeof(struct richace) +
		      unmapped_size;
	struct richacl *acl = kzalloc(size, gfp);

	if (acl) {
		base_acl_init(&acl->a_base);
		acl->a_count = count;
		acl->a_unmapped_size = unmapped_size;
	}
	return acl;
}
EXPORT_SYMBOL_GPL(__richacl_alloc);

/**
 * richacl_clone  -  create a copy of a richacl
 */
struct richacl *
richacl_clone(const struct richacl *acl, gfp_t gfp)
{
	int count = acl->a_count;
	size_t size = sizeof(struct richacl) + count * sizeof(struct richace) +
		      acl->a_unmapped_size;
	struct richacl *dup = kmalloc(size, gfp);

	if (dup) {
		memcpy(dup, acl, size);
		base_acl_init(&dup->a_base);
	}
	return dup;
}

/**
 * richace_copy  -  copy an acl entry
 *
 * If @from has an unmapped who value (from->e_flags & RICHACE_UNMAPPED_WHO),
 * it can only be copied within the same acl!
 */
void
richace_copy(struct richace *to, const struct richace *from)
{
	memcpy(to, from, sizeof(struct richace));
}

/**
 * richacl_add_unmapped_identifier
 * @pacl:	Pointer to an acl
 * @pace:	acl entry within @acl
 * @who:	unmapped identifier
 * @len:	length of @who
 * @gfp:	memory allocation flags
 *
 * Add an unmapped identifier to an acl, possibly reallocating the acl.
 */
int richacl_add_unmapped_identifier(struct richacl **pacl,
				    struct richace **pace,
				    const char *who,
				    unsigned int len, gfp_t gfp)
{
	struct richacl *acl = *pacl;
	size_t size = sizeof(struct richacl) +
		      acl->a_count * sizeof(struct richace) +
		      acl->a_unmapped_size + len + 1;
	unsigned int index = *pace - acl->a_entries;

	acl = krealloc(*pacl, size, gfp);
	if (acl) {
		char *unmapped = (char *)(acl->a_entries + acl->a_count);
		struct richace *ace = acl->a_entries + index;

		ace->e_flags |= RICHACE_UNMAPPED_WHO;
		ace->e_flags &= ~RICHACE_SPECIAL_WHO;
		ace->e_id.offs = acl->a_unmapped_size;
		memcpy(unmapped + ace->e_id.offs, who, len);
		unmapped[ace->e_id.offs + len] = 0;
		acl->a_unmapped_size += len + 1;
		*pace = ace;
		*pacl = acl;
		return 0;
	}
	return -1;
}
EXPORT_SYMBOL_GPL(richacl_add_unmapped_identifier);

/**
 * richace_unmapped_identifier  -  get unmapped identifier
 * @acl:	acl containing @ace
 * @ace:	acl entry
 *
 * Get the unmapped identifier of @ace as a NUL-terminated string, or NULL if
 * @ace doesn't have an unmapped identifier.
 */
const char *richace_unmapped_identifier(const struct richace *ace,
					const struct richacl *acl)
{
	const char *unmapped = (char *)(acl->a_entries + acl->a_count);

	if (!(ace->e_flags & RICHACE_UNMAPPED_WHO))
		return NULL;
	return unmapped + ace->e_id.offs;
}
EXPORT_SYMBOL(richace_unmapped_identifier);

/**
 * richacl_has_unmapped_identifiers
 *
 * Check if an acl has unmapped identifiers.
 */
bool richacl_has_unmapped_identifiers(struct richacl *acl)
{
	struct richace *ace;

	richacl_for_each_entry(ace, acl) {
		if (ace->e_flags & RICHACE_UNMAPPED_WHO)
			return true;
	}
	return false;
}
EXPORT_SYMBOL_GPL(richacl_has_unmapped_identifiers);

/*
 * richacl_mask_to_mode  -  compute the file permission bits from mask
 * @mask:	%RICHACE_* permission mask
 *
 * Compute the file permission bits corresponding to a particular set of
 * richacl permissions.
 *
 * See richacl_masks_to_mode().
 */
static int
richacl_mask_to_mode(unsigned int mask)
{
	int mode = 0;

	if (mask & RICHACE_POSIX_MODE_READ)
		mode |= S_IROTH;
	if (mask & RICHACE_POSIX_MODE_WRITE)
		mode |= S_IWOTH;
	if (mask & RICHACE_POSIX_MODE_EXEC)
		mode |= S_IXOTH;

	return mode;
}

/**
 * richacl_masks_to_mode  -  compute file permission bits from file masks
 *
 * When setting a richacl, we set the file permission bits to indicate maximum
 * permissions: for example, we set the Write permission when a mask contains
 * RICHACE_APPEND_DATA even if it does not also contain RICHACE_WRITE_DATA.
 *
 * Permissions which are not in RICHACE_POSIX_MODE_READ,
 * RICHACE_POSIX_MODE_WRITE, or RICHACE_POSIX_MODE_EXEC cannot be represented
 * in the file permission bits.  Such permissions can still be effective, but
 * not for new files or after a chmod(); they must be explicitly enabled in the
 * richacl.
 */
int
richacl_masks_to_mode(const struct richacl *acl)
{
	return richacl_mask_to_mode(acl->a_owner_mask) << 6 |
	       richacl_mask_to_mode(acl->a_group_mask) << 3 |
	       richacl_mask_to_mode(acl->a_other_mask);
}
EXPORT_SYMBOL_GPL(richacl_masks_to_mode);

/**
 * richacl_mode_to_mask  - compute a file mask from the lowest three mode bits
 * @mode:	mode to convert to richacl permissions
 *
 * When the file permission bits of a file are set with chmod(), this specifies
 * the maximum permissions that processes will get.  All permissions beyond
 * that will be removed from the file masks, and become ineffective.
 */
unsigned int
richacl_mode_to_mask(umode_t mode)
{
	unsigned int mask = 0;

	if (mode & S_IROTH)
		mask |= RICHACE_POSIX_MODE_READ;
	if (mode & S_IWOTH)
		mask |= RICHACE_POSIX_MODE_WRITE;
	if (mode & S_IXOTH)
		mask |= RICHACE_POSIX_MODE_EXEC;

	return mask;
}

/**
 * richacl_want_to_mask  - convert the iop->permission want argument to a mask
 * @want:	@want argument of the permission inode operation
 *
 * When checking for append, create file, create dir, or delete child access,
 * MAY_WRITE is also set in @want.
 */
static unsigned int
richacl_want_to_mask(unsigned int want)
{
	unsigned int mask = 0;

	if (want & MAY_READ)
		mask |= RICHACE_READ_DATA;
	if (want & MAY_DELETE_SELF)
		mask |= RICHACE_DELETE;
	if (want & MAY_TAKE_OWNERSHIP)
		mask |= RICHACE_WRITE_OWNER;
	if (want & MAY_CHMOD)
		mask |= RICHACE_WRITE_ACL;
	if (want & MAY_SET_TIMES)
		mask |= RICHACE_WRITE_ATTRIBUTES;
	if (want & MAY_EXEC)
		mask |= RICHACE_EXECUTE;
	/*
	 * differentiate MAY_WRITE from these request
	 */
	if (want & (MAY_APPEND |
		    MAY_CREATE_FILE | MAY_CREATE_DIR |
		    MAY_DELETE_CHILD)) {
		if (want & MAY_APPEND)
			mask |= RICHACE_APPEND_DATA;
		if (want & MAY_CREATE_FILE)
			mask |= RICHACE_ADD_FILE;
		if (want & MAY_CREATE_DIR)
			mask |= RICHACE_ADD_SUBDIRECTORY;
		if (want & MAY_DELETE_CHILD)
			mask |= RICHACE_DELETE_CHILD;
	} else if (want & MAY_WRITE)
		mask |= RICHACE_WRITE_DATA;
	return mask;
}

/**
 * richacl_permission  -  richacl permission check algorithm
 * @inode:	inode to check
 * @acl:	rich acl of the inode
 * @want:	requested access (MAY_* flags)
 *
 * Checks if the current process is granted @want flags in @acl.
 */
int
richacl_permission(struct user_namespace *mnt_userns,struct inode *inode, const struct richacl *acl,
		   int want)
{
	const struct richace *ace;
	unsigned int mask = richacl_want_to_mask(want);
	unsigned int requested = mask, denied = 0;
	vfsuid_t vfsuid = i_uid_into_vfsuid(mnt_userns, inode);
	vfsgid_t vfsgid = i_gid_into_vfsgid(mnt_userns, inode);
	int in_owning_group = vfsgid_in_group_p(vfsgid);
	int in_owner_or_group_class = in_owning_group;

	/*
	 * A process is
	 *   - in the owner file class if it owns the file,
	 *   - in the group file class if it is in the file's owning group or
	 *     it matches any of the user or group entries, and
	 *   - in the other file class otherwise.
	 * The file class is only relevant for determining which file mask to
	 * apply, which only happens for masked acls.
	 */
	if (acl->a_flags & RICHACL_MASKED) {
		if ((acl->a_flags & RICHACL_WRITE_THROUGH) &&
		    vfsuid_eq_kuid( vfsuid,current_fsuid())) {
			denied = requested & ~acl->a_owner_mask;
			goto out;
		}
	} else {
		/*
		 * When the acl is not masked, there is no need to determine if
		 * the process is in the group class and we can earlier break
		 * out of the loop below.
		 */
		in_owner_or_group_class = 1;
	}

	/*
	 * Check if the acl grants the requested access and determine which
	 * file class the process is in.
	 */
	richacl_for_each_entry(ace, acl) {
		unsigned int ace_mask = ace->e_mask;

		if (richace_is_inherit_only(ace))
			continue;
		if (richace_is_owner(ace)) {
			if (!vfsuid_eq_kuid( vfsuid,current_fsuid()))
				continue;
			goto entry_matches_owner;
		} else if (richace_is_group(ace)) {
			if (!in_owning_group)
				continue;
		} else if (richace_is_unix_user(ace)) {
			if (!uid_eq(current_fsuid(), ace->e_id.uid))
				continue;
			if (vfsuid_eq_kuid( vfsuid,current_fsuid()))
				goto entry_matches_owner;
		} else if (richace_is_unix_group(ace)) {
			if (!in_group_p(ace->e_id.gid))
				continue;
		} else
			goto entry_matches_everyone;

		/*
		 * Apply the group file mask to entries other than owner@ and
		 * everyone@ or user entries matching the owner.  This ensures
		 * that we grant the same permissions as the acl computed by
		 * richacl_apply_masks().
		 *
		 * Without this restriction, the following richacl would grant
		 * rw access to processes which are both the owner and in the
		 * owning group, but not to other users in the owning group,
		 * which could not be represented without masks:
		 *
		 *  owner:rw::mask
		 *  group@:rw::allow
		 */
		if ((acl->a_flags & RICHACL_MASKED) && richace_is_allow(ace))
			ace_mask &= acl->a_group_mask;

entry_matches_owner:
		/* The process is in the owner or group file class. */
		in_owner_or_group_class = 1;

entry_matches_everyone:
		/* Check which mask flags the ACE allows or denies. */
		if (richace_is_deny(ace))
			denied |= ace_mask & mask;
		mask &= ~ace_mask;

		/*
		 * Keep going until we know which file class
		 * the process is in.
		 */
		if (!mask && in_owner_or_group_class)
			break;
	}
	denied |= mask;

	if (acl->a_flags & RICHACL_MASKED) {
		/*
		 * The file class a process is in determines which file mask
		 * applies.  Check if that file mask also grants the requested
		 * access.
		 */
		if (vfsuid_eq_kuid( vfsuid,current_fsuid()))
			denied |= requested & ~acl->a_owner_mask;
		else if (in_owner_or_group_class)
			denied |= requested & ~acl->a_group_mask;
		else {
			if (acl->a_flags & RICHACL_WRITE_THROUGH)
				denied = requested & ~acl->a_other_mask;
			else
				denied |= requested & ~acl->a_other_mask;
		}
	}

out:
	return denied ? -EACCES : 0;
}
EXPORT_SYMBOL_GPL(richacl_permission);

int check_richacl(struct user_namespace *mnt_userns,struct inode *inode, int mask)
{
	if (mask & MAY_NOT_BLOCK) {
		struct base_acl *base_acl;

		base_acl = rcu_dereference(inode->i_acl);
		if (!base_acl)
			return -EAGAIN;
		/* no ->get_richacl() calls in RCU mode... */
		if (is_uncached_acl(base_acl))
			return -ECHILD;
		return richacl_permission(mnt_userns,inode, richacl(base_acl),
					  mask & ~MAY_NOT_BLOCK);
	} else {
		struct richacl *acl;

		acl = get_richacl(inode);
		if (IS_ERR(acl))
			return PTR_ERR(acl);
		if (acl) {
			int error = richacl_permission(mnt_userns,inode, acl, mask);
			richacl_put(acl);
			return error;
		}
	}
	return -EAGAIN;
}

/*
 * Note: functions like richacl_allowed_to_who(), richacl_group_class_allowed(),
 * and richacl_compute_max_masks() iterate through the entire acl in reverse
 * order as an optimization.
 *
 * In the standard algorithm, aces are considered in forward order.  When a
 * process matches an ace, the permissions in the ace are either allowed or
 * denied depending on the ace type.  Once a permission has been allowed or
 * denied, it is no longer considered in further aces.
 *
 * By iterating through the acl in reverse order, we can compute the same
 * result without having to keep track of which permissions have been allowed
 * and denied already.
 */

/**
 * richacl_allowed_to_who  -  permissions allowed to a specific who value
 *
 * Compute the maximum mask values allowed to a specific who value, taking
 * everyone@ aces into account.
 */
static unsigned int richacl_allowed_to_who(struct richacl *acl,
					   struct richace *who)
{
	struct richace *ace;
	unsigned int allowed = 0;

	richacl_for_each_entry_reverse(ace, acl) {
		if (richace_is_inherit_only(ace))
			continue;
		if (richace_is_same_identifier(acl, ace, who) ||
		    richace_is_everyone(ace)) {
			if (richace_is_allow(ace))
				allowed |= ace->e_mask;
			else if (richace_is_deny(ace))
				allowed &= ~ace->e_mask;
		}
	}
	return allowed;
}

/**
 * richacl_group_class_allowed  -  maximum permissions of the group class
 *
 * Compute the maximum mask values allowed to a process in the group class
 * (i.e., a process which is not the owner but is in the owning group or
 * matches a user or group acl entry).  This includes permissions granted or
 * denied by everyone@ aces.
 *
 * See richacl_compute_max_masks().
 */
static unsigned int richacl_group_class_allowed(struct richacl *acl)
{
	struct richace *ace;
	unsigned int everyone_allowed = 0, group_class_allowed = 0;
	int had_group_ace = 0;

	richacl_for_each_entry_reverse(ace, acl) {
		if (richace_is_inherit_only(ace) ||
		    richace_is_owner(ace))
			continue;

		if (richace_is_everyone(ace)) {
			if (richace_is_allow(ace))
				everyone_allowed |= ace->e_mask;
			else if (richace_is_deny(ace))
				everyone_allowed &= ~ace->e_mask;
		} else {
			group_class_allowed |=
				richacl_allowed_to_who(acl, ace);

			if (richace_is_group(ace))
				had_group_ace = 1;
		}
	}
	/*
	 * If the acl doesn't contain any group@ aces, richacl_allowed_to_who()
	 * wasn't called for the owning group.  We could make that call now, but
	 * we already know the result (everyone_allowed).
	 */
	if (!had_group_ace)
		group_class_allowed |= everyone_allowed;
	return group_class_allowed;
}

/**
 * richacl_compute_max_masks  -  compute upper bound masks
 *
 * Computes upper bound owner, group, and other masks so that none of the
 * permissions allowed by the acl are disabled.
 *
 * We don't make assumptions about who the owner is so that the owner can
 * change with no effect on the file masks or file mode permission bits; this
 * means that we must assume that all entries can match the owner.
 */
void richacl_compute_max_masks(struct richacl *acl)
{
	unsigned int gmask = ~0;
	struct richace *ace;

	/*
	 * @gmask contains all permissions which the group class is ever
	 * allowed.  We use it to avoid adding permissions to the group mask
	 * from everyone@ allow aces which the group class is always denied
	 * through other aces.  For example, the following acl would otherwise
	 * result in a group mask of rw:
	 *
	 *	group@:w::deny
	 *	everyone@:rw::allow
	 *
	 * Avoid computing @gmask for acls which do not include any group class
	 * deny aces: in such acls, the group class is never denied any
	 * permissions from everyone@ allow aces, and the group class cannot
	 * have fewer permissions than the other class.
	 */

restart:
	acl->a_owner_mask = 0;
	acl->a_group_mask = 0;
	acl->a_other_mask = 0;

	richacl_for_each_entry_reverse(ace, acl) {
		if (richace_is_inherit_only(ace))
			continue;

		if (richace_is_owner(ace)) {
			if (richace_is_allow(ace))
				acl->a_owner_mask |= ace->e_mask;
			else if (richace_is_deny(ace))
				acl->a_owner_mask &= ~ace->e_mask;
		} else if (richace_is_everyone(ace)) {
			if (richace_is_allow(ace)) {
				acl->a_owner_mask |= ace->e_mask;
				acl->a_group_mask |= ace->e_mask & gmask;
				acl->a_other_mask |= ace->e_mask;
			} else if (richace_is_deny(ace)) {
				acl->a_owner_mask &= ~ace->e_mask;
				acl->a_group_mask &= ~ace->e_mask;
				acl->a_other_mask &= ~ace->e_mask;
			}
		} else {
			if (richace_is_allow(ace)) {
				acl->a_owner_mask |= ace->e_mask & gmask;
				acl->a_group_mask |= ace->e_mask & gmask;
			} else if (richace_is_deny(ace) && gmask == ~0) {
				gmask = richacl_group_class_allowed(acl);
				if (likely(gmask != ~0))
					/* should always be true */
					goto restart;
			}
		}
	}

	acl->a_flags &= ~(RICHACL_WRITE_THROUGH | RICHACL_MASKED);
}
EXPORT_SYMBOL_GPL(richacl_compute_max_masks);

/**
 * set_richacl  -  set the richacl of an inode
 * @inode:	inode whose richacl to set
 * @acl:	access control list
 */
int
set_richacl(struct user_namespace *mnt_userns,struct inode *inode, struct richacl *acl)
{
	if (!IS_RICHACL(inode))
		return -EOPNOTSUPP;
	if (!inode->i_op->set_richacl)
		return -EOPNOTSUPP;

	if (!vfsuid_eq_kuid( i_uid_into_vfsuid(mnt_userns, inode),current_fsuid()) &&
	    inode_permission(mnt_userns,inode, MAY_CHMOD) &&
	    !capable(CAP_FOWNER))
		return -EPERM;

	return inode->i_op->set_richacl(mnt_userns,inode, acl);
}
EXPORT_SYMBOL(set_richacl);

/**
 * __richacl_chmod  -  update the file masks to reflect the new mode
 * @acl:	access control list
 * @mode:	new file permission bits including the file type
 *
 * Return a copy of @acl where the file masks have been replaced by the file
 * masks corresponding to the file permission bits in @mode, or returns @acl
 * itself if the file masks are already up to date.  Takes over a reference
 * to @acl.
 */
static struct richacl *
__richacl_chmod(struct richacl *acl, umode_t mode)
{
	unsigned int x = S_ISDIR(mode) ? 0 : RICHACE_DELETE_CHILD;
	unsigned int owner_mask, group_mask, other_mask;
	struct richacl *clone;

	owner_mask = richacl_mode_to_mask(mode >> 6) & ~x;
	group_mask = richacl_mode_to_mask(mode >> 3) & ~x;
	other_mask = richacl_mode_to_mask(mode)      & ~x;

	if (acl->a_owner_mask == owner_mask &&
	    acl->a_group_mask == group_mask &&
	    acl->a_other_mask == other_mask &&
	    (acl->a_flags & RICHACL_MASKED) &&
	    (acl->a_flags & RICHACL_WRITE_THROUGH) &&
	    (!richacl_is_auto_inherit(acl) || richacl_is_protected(acl)))
		return acl;

	clone = richacl_clone(acl, GFP_KERNEL);
	richacl_put(acl);
	if (!clone)
		return ERR_PTR(-ENOMEM);

	clone->a_flags |= (RICHACL_WRITE_THROUGH | RICHACL_MASKED);
	clone->a_owner_mask = owner_mask;
	clone->a_group_mask = group_mask;
	clone->a_other_mask = other_mask;
	if (richacl_is_auto_inherit(clone))
		clone->a_flags |= RICHACL_PROTECTED;

	return clone;
}

/**
 * richacl_chmod  -  filesystem chmod helper
 * @inode:	inode whose file permission bits to change
 * @mode:	new file permission bits including the file type
 *
 * Helper for filesystems to use to perform a chmod on the richacl of an inode.
 */
int
richacl_chmod(struct user_namespace *nt_userns, struct inode *inode, umode_t mode)
{
	struct richacl *acl;
	int retval;

	if (S_ISLNK(mode))
		return -EOPNOTSUPP;
	if (!inode->i_op->set_richacl)
		return -EOPNOTSUPP;
	acl = get_richacl(inode);
	if (IS_ERR_OR_NULL(acl))
		return PTR_ERR(acl);
	acl = __richacl_chmod(acl, mode);
	if (IS_ERR(acl))
		return PTR_ERR(acl);
	retval = inode->i_op->set_richacl(nt_userns,inode, acl);
	richacl_put(acl);

	return retval;
}
EXPORT_SYMBOL(richacl_chmod);

/**
 * richacl_equiv_mode  -  compute the mode equivalent of @acl
 *
 * An acl is considered equivalent to a file mode if it only consists of
 * owner@, group@, and everyone@ entries and the owner@ permissions do not
 * depend on whether the owner is a member in the owning group.
 */
int
richacl_equiv_mode(const struct richacl *acl, umode_t *mode_p)
{
	umode_t mode = *mode_p;

	/*
	 * The RICHACE_DELETE_CHILD flag is meaningless for non-directories, so
	 * we ignore it.
	 */
	unsigned int x = S_ISDIR(mode) ? 0 : RICHACE_DELETE_CHILD;
	struct {
		unsigned int allowed;
		unsigned int defined;  /* allowed or denied */
	} owner = {
		.defined = RICHACE_POSIX_ALWAYS_ALLOWED |
			   RICHACE_POSIX_OWNER_ALLOWED  | x,
	}, group = {
		.defined = RICHACE_POSIX_ALWAYS_ALLOWED | x,
	}, everyone = {
		.defined = RICHACE_POSIX_ALWAYS_ALLOWED | x,
	};
	const struct richace *ace;

	if (acl->a_flags & ~(RICHACL_WRITE_THROUGH | RICHACL_MASKED))
		return -1;

	richacl_for_each_entry(ace, acl) {
		if (ace->e_flags & ~RICHACE_SPECIAL_WHO)
			return -1;

		if (richace_is_owner(ace) || richace_is_everyone(ace)) {
			x = ace->e_mask & ~owner.defined;
			if (richace_is_allow(ace)) {
				unsigned int group_denied =
					group.defined & ~group.allowed;

				if (x & group_denied)
					return -1;
				owner.allowed |= x;
			} else /* if (richace_is_deny(ace)) */ {
				if (x & group.allowed)
					return -1;
			}
			owner.defined |= x;

			if (richace_is_everyone(ace)) {
				x = ace->e_mask;
				if (richace_is_allow(ace)) {
					group.allowed |=
						x & ~group.defined;
					everyone.allowed |=
						x & ~everyone.defined;
				}
				group.defined |= x;
				everyone.defined |= x;
			}
		} else if (richace_is_group(ace)) {
			x = ace->e_mask & ~group.defined;
			if (richace_is_allow(ace))
				group.allowed |= x;
			group.defined |= x;
		} else
			return -1;
	}

	if (group.allowed & ~owner.defined)
		return -1;

	if (acl->a_flags & RICHACL_MASKED) {
		if (acl->a_flags & RICHACL_WRITE_THROUGH) {
			owner.allowed = acl->a_owner_mask;
			everyone.allowed = acl->a_other_mask;
		} else {
			owner.allowed &= acl->a_owner_mask;
			everyone.allowed &= acl->a_other_mask;
		}
		group.allowed &= acl->a_group_mask;
	}

	mode = (mode & ~S_IRWXUGO) |
	       (richacl_mask_to_mode(owner.allowed) << 6) |
	       (richacl_mask_to_mode(group.allowed) << 3) |
		richacl_mask_to_mode(everyone.allowed);

	/* Mask flags we can ignore */
	x = S_ISDIR(mode) ? 0 : RICHACE_DELETE_CHILD;

	if (((richacl_mode_to_mask(mode >> 6) ^ owner.allowed)    & ~x) ||
	    ((richacl_mode_to_mask(mode >> 3) ^ group.allowed)    & ~x) ||
	    ((richacl_mode_to_mask(mode)      ^ everyone.allowed) & ~x))
		return -1;

	*mode_p = mode;
	return 0;
}
EXPORT_SYMBOL_GPL(richacl_equiv_mode);

static inline bool
ace_inherits_to_directory(const struct richace *ace)
{
	if (ace->e_flags & RICHACE_DIRECTORY_INHERIT_ACE)
		return true;
	if ((ace->e_flags & RICHACE_FILE_INHERIT_ACE) &&
	    !(ace->e_flags & RICHACE_NO_PROPAGATE_INHERIT_ACE))
		return true;
	return false;
}

/**
 * richacl_inherit  -  compute the inherited acl of a new file
 * @dir_acl:	acl of the containing directory
 * @isdir:	inherit by a directory or non-directory?
 *
 * A directory can have acl entries which files and/or directories created
 * inside the directory will inherit.  This function computes the acl for such
 * a new file.  If there is no inheritable acl, it will return %NULL.
 */
struct richacl *
richacl_inherit(const struct richacl *dir_acl, int isdir)
{
	const struct richace *dir_ace;
	struct richacl *acl = NULL;
	struct richace *ace;
	unsigned int count = 0, unmapped_size = 0, offset = 0;
	const char *dir_unmapped;
	char *unmapped;

	if (isdir) {
		richacl_for_each_entry(dir_ace, dir_acl) {
			if (!ace_inherits_to_directory(dir_ace))
				continue;

			count++;
			dir_unmapped =
				richace_unmapped_identifier(dir_ace, dir_acl);
			if (dir_unmapped)
				unmapped_size += strlen(dir_unmapped) + 1;
		}
		if (!count)
			return NULL;
		acl = __richacl_alloc(count, unmapped_size, GFP_KERNEL);
		if (!acl)
			return ERR_PTR(-ENOMEM);
		ace = acl->a_entries;
		unmapped = (char *)(acl->a_entries + acl->a_count);
		richacl_for_each_entry(dir_ace, dir_acl) {
			if (!ace_inherits_to_directory(dir_ace))
				continue;

			richace_copy(ace, dir_ace);
			if (dir_ace->e_flags & RICHACE_NO_PROPAGATE_INHERIT_ACE)
				ace->e_flags &= ~RICHACE_INHERITANCE_FLAGS;
			else if (dir_ace->e_flags & RICHACE_DIRECTORY_INHERIT_ACE)
				ace->e_flags &= ~RICHACE_INHERIT_ONLY_ACE;
			else
				ace->e_flags |= RICHACE_INHERIT_ONLY_ACE;

			dir_unmapped =
				richace_unmapped_identifier(dir_ace, dir_acl);
			if (dir_unmapped) {
				size_t sz = strlen(dir_unmapped) + 1;

				ace->e_id.offs = offset;
				memcpy(unmapped, dir_unmapped, sz);
				unmapped += sz;
				offset += sz;
			}
			ace++;
		}
	} else {
		richacl_for_each_entry(dir_ace, dir_acl) {
			if (!(dir_ace->e_flags & RICHACE_FILE_INHERIT_ACE))
				continue;

			count++;
			dir_unmapped =
				richace_unmapped_identifier(dir_ace, dir_acl);
			if (dir_unmapped)
				unmapped_size += strlen(dir_unmapped) + 1;
		}
		if (!count)
			return NULL;
		acl = __richacl_alloc(count, unmapped_size, GFP_KERNEL);
		if (!acl)
			return ERR_PTR(-ENOMEM);
		ace = acl->a_entries;
		unmapped = (char *)(acl->a_entries + acl->a_count);
		richacl_for_each_entry(dir_ace, dir_acl) {
			if (!(dir_ace->e_flags & RICHACE_FILE_INHERIT_ACE))
				continue;

			richace_copy(ace, dir_ace);
			ace->e_flags &= ~RICHACE_INHERITANCE_FLAGS;
			/*
			 * RICHACE_DELETE_CHILD is meaningless for
			 * non-directories, so clear it.
			 */
			ace->e_mask &= ~RICHACE_DELETE_CHILD;

			dir_unmapped =
				richace_unmapped_identifier(dir_ace, dir_acl);
			if (dir_unmapped) {
				size_t sz = strlen(dir_unmapped) + 1;

				ace->e_id.offs = offset;
				memcpy(unmapped, dir_unmapped, sz);
				unmapped += sz;
				offset += sz;
			}
			ace++;
		}
	}
	if (richacl_is_auto_inherit(dir_acl)) {
		acl->a_flags = RICHACL_AUTO_INHERIT;
		richacl_for_each_entry(ace, acl)
			ace->e_flags |= RICHACE_INHERITED_ACE;
	} else {
		richacl_for_each_entry(ace, acl)
			ace->e_flags &= ~RICHACE_INHERITED_ACE;
	}

	return acl;
}

/*
 * richacl_inherit_inode  -  compute inherited acl and file mode
 * @dir_acl:	acl of the containing directory
 * @mode_p:	mode of the new inode
 *
 * The file permission bits in @mode_p must be set to the create mode by the
 * caller.
 *
 * If there is an inheritable acl, the maximum permissions that the acl grants
 * are computed and the file masks of the new acl are set accordingly.
 */
static struct richacl *
richacl_inherit_inode(const struct richacl *dir_acl, umode_t *mode_p)
{
	struct richacl *acl;
	umode_t mode = *mode_p;

	acl = richacl_inherit(dir_acl, S_ISDIR(mode));
	if (acl) {
		if (richacl_equiv_mode(acl, &mode) == 0) {
			*mode_p &= mode;
			richacl_put(acl);
			acl = NULL;
		} else {
			/*
			 * We need to set RICHACL_PROTECTED because we are
			 * doing an implicit chmod
			 */
			if (richacl_is_auto_inherit(acl))
				acl->a_flags |= RICHACL_PROTECTED;

			richacl_compute_max_masks(acl);
			/*
			 * Ensure that the acl will not grant any permissions
			 * beyond the create mode.
			 */
			acl->a_flags |= RICHACL_MASKED;
			acl->a_owner_mask &=
				richacl_mode_to_mask(mode >> 6);
			acl->a_group_mask &=
				richacl_mode_to_mask(mode >> 3);
			acl->a_other_mask &=
				richacl_mode_to_mask(mode);
		}
	} else
		*mode_p &= ~current_umask();

	return acl;
}

/**
 * richacl_create  -  filesystem create helper
 * @mode_p:	mode of the new inode
 * @dir:	containing directory
 *
 * Compute the inherited acl for a new inode.  If there is no acl to inherit,
 * apply the umask.  Use when creating a new inode on a richacl enabled file
 * system.
 */
struct richacl *richacl_create(umode_t *mode_p, struct inode *dir)
{
	struct richacl *dir_acl, *acl = NULL;

	if (S_ISLNK(*mode_p))
		return NULL;
	dir_acl = get_richacl(dir);
	if (dir_acl) {
		if (IS_ERR(dir_acl))
			return dir_acl;
		acl = richacl_inherit_inode(dir_acl, mode_p);
		richacl_put(dir_acl);
	} else
		*mode_p &= ~current_umask();
	return acl;
}
EXPORT_SYMBOL_GPL(richacl_create);
