#ifndef __LINUX_ACL_H
#define __LINUX_ACL_H

#include <linux/posix_acl.h>
#include <linux/richacl.h>

static inline int
acl_chmod(struct user_namespace *mnt_userns, struct inode *inode)
{
	if (IS_RICHACL(inode))
		return richacl_chmod(mnt_userns, inode, inode->i_mode);
	return posix_acl_chmod(mnt_userns, inode, inode->i_mode);
}

#endif
