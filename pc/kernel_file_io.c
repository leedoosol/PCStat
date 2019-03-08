#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/sched.h>
#include <linux/file.h>

#include <asm/processor.h>
#include <asm/uaccess.h>

#include "kernel_file_io.h"


struct file* file_open(const char* file_name, int flags, int mode)
{
	struct file* filp = filp_open(file_name, flags, mode);

	if(IS_ERR(filp))
	{
		printk(KERN_INFO "file_open_error:%ld", PTR_ERR(filp));
		return NULL;
	}
	else
	{
		return filp;
	}

}

void file_close(struct file* filp)
{
	if(filp != NULL)
	{
		filp_close(filp, NULL);
	}
}

uint64_t file_seek(struct file* filp, uint64_t offset, int whence)
{
	uint64_t pos = filp->f_pos;

	if(filp != NULL)
	{
		if(whence == SEEK_SET)
		{
			pos = offset;
		}
		else if(whence == SEEK_CUR)
		{
			pos += offset;
		}
		
		if(pos < 0)
		{
			pos = 0;
		}

		return(filp->f_pos = (loff_t) pos);
	}
	else
	{
		return -ENOENT;
	}
}

int file_read(char* buf, int len, struct file *filp)
{
	int read_len;
	mm_segment_t oldfs;

	if(filp == NULL)
	{
		return -ENOENT;
	}

	/* patch for linux 4.x: filp->f_op->read is disabled. use __vfs_read instead. */
	//if(filp->f_op->read == NULL)
	//{
	//	return -ENOSYS;
	//}

	if(((filp->f_flags & O_ACCMODE) & O_RDONLY) != 0)
	{
		return -EACCES;
	}

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	//read_len = filp->f_op->read(filp, buf, len, &filp->f_pos);
	read_len = __vfs_read(filp, buf, len, &filp->f_pos);
	set_fs(oldfs);

	return read_len;
}

int file_write(char* buf, int len, struct file *filp)
{
	int write_len;
	mm_segment_t oldfs;

	if(filp == NULL)
	{
		return -ENOENT;
	}

	/* patch for linux 4.x: filp->f_op->write is disabled. use __vfs_write instead. */
	//if(filp->f_op->write == NULL)
	//{
	//	return -ENOSYS;
	//}

	if(((filp->f_flags & O_ACCMODE) & (O_WRONLY | O_RDWR)) == 0)
	{
		return -EACCES;
	}

	oldfs = get_fs();
	set_fs(KERNEL_DS);
	//write_len = filp->f_op->write(filp, buf, len, &filp->f_pos);
	write_len = __vfs_write(filp, buf, len, &filp->f_pos);
	set_fs(oldfs);

	return write_len;
}
