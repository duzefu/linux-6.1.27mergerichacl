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

#ifndef __RICHACL_H
#define __RICHACL_H

#include <uapi/linux/richacl.h>

struct richace {
	unsigned short	e_type;
	unsigned short	e_flags;
	unsigned int	e_mask;
	union {
		kuid_t		uid;
		kgid_t		gid;
		unsigned int	special;
		unsigned short	offs;  /* unmapped offset */
	} e_id;
};

struct richacl {
	struct base_acl	a_base;  /* must be first, see richacl_put() */
	unsigned int	a_owner_mask;
	unsigned int	a_group_mask;
	unsigned int	a_other_mask;
	unsigned short	a_count;
	unsigned short	a_flags;
	unsigned short	a_unmapped_size;
	struct richace	a_entries[0];
};

#define richacl_for_each_entry(_ace, _acl)			\
	for (_ace = (_acl)->a_entries;				\
	     _ace != (_acl)->a_entries + (_acl)->a_count;	\
	     _ace++)

#define richacl_for_each_entry_reverse(_ace, _acl)		\
	for (_ace = (_acl)->a_entries + (_acl)->a_count - 1;	\
	     _ace != (_acl)->a_entries - 1;			\
	     _ace--)

/**
 * richacl_get  -  grab another reference to a richacl handle
 */
static inline struct richacl *
richacl_get(struct richacl *acl)
{
	base_acl_get(&acl->a_base);
	return acl;
}

/**
 * richacl_put  -  free a richacl handle
 */
static inline void
richacl_put(struct richacl *acl)
{
	BUILD_BUG_ON(offsetof(struct richacl, a_base) != 0);
	base_acl_put(&acl->a_base);
}

static inline struct richacl *
richacl(struct base_acl *base_acl)
{
	BUILD_BUG_ON(offsetof(struct richacl, a_base) != 0);
	return container_of(base_acl, struct richacl, a_base);
}

extern void set_cached_richacl(struct inode *, struct richacl *);
extern void forget_cached_richacl(struct inode *);
extern struct richacl *get_richacl(struct inode *);

static inline int
richacl_is_auto_inherit(const struct richacl *acl)
{
	return acl->a_flags & RICHACL_AUTO_INHERIT;
}

static inline int
richacl_is_protected(const struct richacl *acl)
{
	return acl->a_flags & RICHACL_PROTECTED;
}

/**
 * richace_is_owner  -  check if @ace is an OWNER@ entry
 */
static inline bool
richace_is_owner(const struct richace *ace)
{
	return (ace->e_flags & RICHACE_SPECIAL_WHO) &&
	       ace->e_id.special == RICHACE_OWNER_SPECIAL_ID;
}

/**
 * richace_is_group  -  check if @ace is a GROUP@ entry
 */
static inline bool
richace_is_group(const struct richace *ace)
{
	return (ace->e_flags & RICHACE_SPECIAL_WHO) &&
	       ace->e_id.special == RICHACE_GROUP_SPECIAL_ID;
}

/**
 * richace_is_everyone  -  check if @ace is an EVERYONE@ entry
 */
static inline bool
richace_is_everyone(const struct richace *ace)
{
	return (ace->e_flags & RICHACE_SPECIAL_WHO) &&
	       ace->e_id.special == RICHACE_EVERYONE_SPECIAL_ID;
}

/**
 * richace_is_unix_user  -  check if @ace applies to a specific user
 */
static inline bool
richace_is_unix_user(const struct richace *ace)
{
	return !(ace->e_flags & RICHACE_SPECIAL_WHO) &&
	       !(ace->e_flags & RICHACE_IDENTIFIER_GROUP);
}

/**
 * richace_is_unix_group  -  check if @ace applies to a specific group
 */
static inline bool
richace_is_unix_group(const struct richace *ace)
{
	return !(ace->e_flags & RICHACE_SPECIAL_WHO) &&
	       (ace->e_flags & RICHACE_IDENTIFIER_GROUP);
}

/**
 * richace_is_inherit_only  -  check if @ace is for inheritance only
 *
 * ACEs with the %RICHACE_INHERIT_ONLY_ACE flag set have no effect during
 * permission checking.
 */
static inline bool
richace_is_inherit_only(const struct richace *ace)
{
	return ace->e_flags & RICHACE_INHERIT_ONLY_ACE;
}

/**
 * richace_is_inheritable  -  check if @ace is inheritable
 */
static inline bool
richace_is_inheritable(const struct richace *ace)
{
	return ace->e_flags & (RICHACE_FILE_INHERIT_ACE |
			       RICHACE_DIRECTORY_INHERIT_ACE);
}

/**
 * richace_is_allow  -  check if @ace is an %ALLOW type entry
 */
static inline bool
richace_is_allow(const struct richace *ace)
{
	return ace->e_type == RICHACE_ACCESS_ALLOWED_ACE_TYPE;
}

/**
 * richace_is_deny  -  check if @ace is a %DENY type entry
 */
static inline bool
richace_is_deny(const struct richace *ace)
{
	return ace->e_type == RICHACE_ACCESS_DENIED_ACE_TYPE;
}

/**
 * richace_is_same_identifier  -  are both identifiers the same?
 */
static inline bool
richace_is_same_identifier(const struct richacl *acl,
			   const struct richace *ace1,
			   const struct richace *ace2)
{
	const char *unmapped = (char *)(acl->a_entries + acl->a_count);

	return !((ace1->e_flags ^ ace2->e_flags) &
		 (RICHACE_SPECIAL_WHO |
		  RICHACE_IDENTIFIER_GROUP |
		  RICHACE_UNMAPPED_WHO)) &&
	       ((ace1->e_flags & RICHACE_UNMAPPED_WHO) ?
		!strcmp(unmapped + ace1->e_id.offs,
			unmapped + ace2->e_id.offs) :
		!memcmp(&ace1->e_id, &ace2->e_id, sizeof(ace1->e_id)));
}

extern struct richacl *__richacl_alloc(unsigned int, size_t, gfp_t);
static inline struct richacl *richacl_alloc(unsigned int count, gfp_t gfp)
{
	return __richacl_alloc(count, 0, gfp);
}

extern struct richacl *richacl_clone(const struct richacl *, gfp_t);
extern void richace_copy(struct richace *, const struct richace *);
extern int richacl_masks_to_mode(const struct richacl *);
extern unsigned int richacl_mode_to_mask(umode_t);
extern int richacl_permission(struct user_namespace *,struct inode *, const struct richacl *, int);
extern void richacl_compute_max_masks(struct richacl *);
extern int richacl_chmod(struct user_namespace *,struct inode *, umode_t);
extern int richacl_equiv_mode(const struct richacl *, umode_t *);
extern struct richacl *richacl_inherit(const struct richacl *, int);
extern struct richacl *richacl_create(umode_t *, struct inode *);
extern int set_richacl(struct user_namespace *,struct inode *, struct richacl *);
extern int richacl_add_unmapped_identifier(struct richacl **, struct richace **,
					   const char *, unsigned int, gfp_t);
extern const char *richace_unmapped_identifier(const struct richace *,
					       const struct richacl *);
extern bool richacl_has_unmapped_identifiers(struct richacl *);

/* richacl_compat.c */
extern int richacl_apply_masks(struct richacl **, kuid_t);
extern struct richacl *richacl_from_mode(umode_t);

#ifdef CONFIG_FS_RICHACL
extern int check_richacl(struct user_namespace *,struct inode *, int);
#else
static inline int check_richacl(struct user_namespace *mnt_userns,struct inode *inode, int mask) {
	return -EAGAIN;
}
#endif  /* CONFIG_FS_RICHACL */

#endif /* __RICHACL_H */
