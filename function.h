#include "lsmt_ro_file.h"

#ifndef __KERNEL__

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#else

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/string.h>
#include <linux/stat.h>
#include <linux/slab.h>
#include <linux/export.h>
#include <linux/vfs.h>
#include <linux/mm.h>
#include <linux/fs.h>
#include <linux/file.h>
#include <linux/mm.h>

#endif

int _lsmt_fstat(void *fd, void *stat)
{
#ifndef __KERNEL__
        return fstat((int)(uint64_t)fd, (struct stat *)stat);
#else
        return vfs_fstat(fd, &stat);
#endif
}

ssize_t _lsmt_pread(void *fd, void *buf, size_t n, off_t offset)
{
#ifndef __KERNEL__
        return pread((int)(uint64_t)fd, buf, n, offset);
#else
        return ksys_pread64(fd, buf, n, offset);
#endif
}

void *_lsmt_malloc(size_t size)
{
#ifndef __KERNEL__
        return malloc(size);
#else
        return kvmalloc(size, GFP_KERNEL);
#endif
}

void *_lsmt_realloc(void *ptr, size_t size)
{
#ifndef __KERNEL__
        return realloc(ptr, size);
#else
        return kreaalloc(ptr, size, GFP_KERNEL);
#endif     
}

void _lsmt_free(void *ptr)
{
#ifndef __KERNEL__
        free(ptr);
#else
        kfree(ptr);
#endif
}