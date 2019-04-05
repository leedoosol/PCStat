/*
 * kernel/pc.c: user-level pc collection
 */

#include <linux/unistd.h>
#include <linux/errno.h>
#include <linux/kernel.h>
#include <linux/sched.h>
#include <linux/slab.h> 
#include <linux/stat.h>
#include <linux/fcntl.h>
#include <linux/file.h>
#include <linux/uio.h>
#include <linux/fsnotify.h>
#include <linux/security.h>
#include <linux/export.h>
#include <linux/syscalls.h>
#include <linux/pagemap.h>
#include <linux/splice.h>
#include <linux/compat.h>
#include <linux/mount.h>
#include <linux/fs.h>
#include <linux/module.h>

#include <asm/processor.h>
#include <asm/uaccess.h>
#include <asm/unistd.h>
#include <asm/percpu.h>
#include <asm/syscall.h>
#include <asm/ptrace.h>
#include <linux/ktime.h>

#define ADDRESS_UNIT 4
#define NUM_RET_ADDR_THRESHOLD 10
#define ValueOf(ptr) (*((unsigned long *) (ptr)))

/* file I/O functions */

static struct file* file_open(const char* file_name, int flags, int mode)
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

static void file_close(struct file* filp)
{
	if(filp != NULL)
	{
		filp_close(filp, NULL);
	}
}

static int file_write(char* buf, int len, struct file *filp)
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

typedef unsigned long (*PCFunc)(void);
PCFunc record_pc = NULL;
int set_record_pc (PCFunc fn)
{
	record_pc = fn;
	return 0;
}
EXPORT_SYMBOL(set_record_pc);

/**
 * sys_get_pc: syscall for collecting current PCs
 */
asmlinkage unsigned long sys_get_pc()
{
	if (record_pc != NULL)
		return record_pc();

	return 0;
}

/* I/O syscalls with PC signature */

#define IO_READ		0
#define IO_PREAD64	1
#define IO_READV	2
#define IO_PREADV	3
#define IO_WRITE	4
#define IO_PWRITE64	5
#define IO_WRITEV	6
#define IO_PWRITEV	7

typedef void (*PCFuncType)(unsigned int, struct file*, unsigned int, unsigned int, unsigned long, loff_t, ktime_t, ktime_t, long);
PCFuncType record_syscall = NULL;

int set_record_syscall (PCFuncType fn)
{
	record_syscall = fn;
	return 0;
}
EXPORT_SYMBOL(set_record_syscall);

static int record_request_without_pc(unsigned int fd, struct file *file, unsigned int count,
			 unsigned int type, unsigned long oldrsp, loff_t pos, ktime_t start, ktime_t end, long pc_sig)
{
	if (fd >= 2)
	{
		if (record_syscall != NULL)
		{
			record_syscall(fd, file, count, type, oldrsp, pos, start, end, pc_sig);
		}
	}

	return 0;
}

static inline void fdput_pos(struct fd f)
{
	if (f.flags & FDPUT_POS_UNLOCK)
		mutex_unlock(&f.file->f_pos_lock);
	fdput(f);
}

SYSCALL_DEFINE4(read_pc, unsigned int, fd, char __user *, buf, size_t, count, long, pc_sig)
{
	struct fd f = __to_fd(__fdget_pos(fd));
	ssize_t ret = -EBADF;
	unsigned long oldrsp;
	ktime_t start, end;

	if (f.file) {
		start = ktime_get();

		loff_t pos = f.file->f_pos;
		loff_t prev_pos = pos;
		ret = vfs_read(f.file, buf, count, &pos);
		if (ret >= 0)
			f.file->f_pos = pos;
		fdput_pos(f);

		end = ktime_get();
		oldrsp = current_pt_regs()->sp;
		record_request_without_pc(fd, f.file, count, IO_READ, oldrsp, prev_pos, start, end, pc_sig);
	}
	return ret;
}


SYSCALL_DEFINE4(write_pc, unsigned int, fd, const char __user *, buf, size_t, count, long, pc_sig)
{
	struct fd f = __to_fd(__fdget_pos(fd));
	ssize_t ret = -EBADF;
	unsigned long oldrsp;
	ktime_t start, end;

	if (f.file) {
		start = ktime_get();

		loff_t pos = f.file->f_pos;
		loff_t prev_pos = pos;
		ret = vfs_write(f.file, buf, count, &pos);
		if (ret >= 0)
			f.file->f_pos = pos;
		fdput_pos(f);

		end = ktime_get();
		oldrsp = current_pt_regs()->sp;
		record_request_without_pc(fd, f.file, count, IO_WRITE, oldrsp, prev_pos, start, end, pc_sig);
	}

	return ret;
}

SYSCALL_DEFINE5(pread64_pc, unsigned int, fd, char __user *, buf, size_t, count, loff_t, pos, long, pc_sig)
{
	struct fd f;
	ssize_t ret = -EBADF;
	unsigned long oldrsp;
	ktime_t start, end;

	if (pos < 0)
		return -EINVAL;

	f = fdget(fd);
	if (f.file) {
		start = ktime_get();

		loff_t prev_pos = pos;
		ret = -ESPIPE;
		if (f.file->f_mode & FMODE_PREAD)
			ret = vfs_read(f.file, buf, count, &pos);
		fdput(f);

		end = ktime_get();
		oldrsp = current_pt_regs()->sp;
		record_request_without_pc(fd, f.file, count, IO_PREAD64, oldrsp, prev_pos, start, end, pc_sig);
	}

	return ret;
}

SYSCALL_DEFINE5(pwrite64_pc, unsigned int, fd, const char __user *, buf, size_t, count, loff_t, pos, long, pc_sig)
{
	struct fd f;
	ssize_t ret = -EBADF;
	unsigned long oldrsp;
	ktime_t start, end;

	if (pos < 0)
		return -EINVAL;

	f = fdget(fd);
	if (f.file) {
		start = ktime_get();

		loff_t prev_pos = pos;
		ret = -ESPIPE;
		if (f.file->f_mode & FMODE_PWRITE)  
			ret = vfs_write(f.file, buf, count, &pos);
		fdput(f);

		end = ktime_get();
		oldrsp = current_pt_regs()->sp;
		record_request_without_pc(fd, f.file, count, IO_PWRITE64, oldrsp, prev_pos, start, end, pc_sig);
	}

	return ret;
}

SYSCALL_DEFINE4(readv_pc, unsigned long, fd, const struct iovec __user *, vec, unsigned long, vlen, long, pc_sig)
{
	struct fd f = __to_fd(__fdget_pos(fd));
	ssize_t ret = -EBADF;
	unsigned long oldrsp;
	ktime_t start, end;

	if (f.file) {
		start = ktime_get();

		loff_t pos = f.file->f_pos;
		loff_t prev_pos = pos;
		ret = vfs_readv(f.file, vec, vlen, &pos);
		if (ret >= 0)
			f.file->f_pos = pos;
		fdput_pos(f);

		end = ktime_get();
		oldrsp = current_pt_regs()->sp;
		record_request_without_pc(fd, f.file, vlen, IO_READV, oldrsp, prev_pos, start, end, pc_sig);
	}

	if (ret > 0)
		add_rchar(current, ret);
	inc_syscr(current);
	return ret;
}

SYSCALL_DEFINE4(writev_pc, unsigned long, fd, const struct iovec __user *, vec, unsigned long, vlen, long, pc_sig)
{
	struct fd f = __to_fd(__fdget_pos(fd));
	ssize_t ret = -EBADF;
	unsigned long oldrsp;
	ktime_t start, end;

	if (f.file) {
		start = ktime_get();

		loff_t pos = f.file->f_pos;
		loff_t prev_pos = pos;
		ret = vfs_writev(f.file, vec, vlen, &pos);
		if (ret >= 0)
			f.file->f_pos = pos;
		fdput_pos(f);

		end = ktime_get();
		oldrsp = current_pt_regs()->sp;
		record_request_without_pc(fd, f.file, vlen, IO_WRITEV, oldrsp, prev_pos, start, end, pc_sig);
	}

	if (ret > 0)
		add_wchar(current, ret);
	inc_syscw(current);
	return ret;
}

static inline loff_t pos_from_hilo(unsigned long high, unsigned long low)
{
#define HALF_LONG_BITS (BITS_PER_LONG / 2)
	return (((loff_t)high << HALF_LONG_BITS) << HALF_LONG_BITS) | low;
}

SYSCALL_DEFINE6(preadv_pc, unsigned long, fd, const struct iovec __user *, vec,
		unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h, long, pc_sig)
{
	loff_t pos = pos_from_hilo(pos_h, pos_l);
	struct fd f;
	ssize_t ret = -EBADF;
	unsigned long oldrsp;
	ktime_t start, end;

	if (pos < 0)
		return -EINVAL;

	f = fdget(fd);
	if (f.file) {
		start = ktime_get();

		loff_t prev_pos = pos;

		ret = -ESPIPE;
		if (f.file->f_mode & FMODE_PREAD)
			ret = vfs_readv(f.file, vec, vlen, &pos);
		fdput(f);

		end = ktime_get();
		oldrsp = current_pt_regs()->sp;
		record_request_without_pc(fd, f.file, vlen, IO_PREADV, oldrsp, prev_pos, start, end, pc_sig);
	}

	if (ret > 0)
		add_rchar(current, ret);
	inc_syscr(current);
	return ret;
}

SYSCALL_DEFINE6(pwritev_pc, unsigned long, fd, const struct iovec __user *, vec,
		unsigned long, vlen, unsigned long, pos_l, unsigned long, pos_h, long, pc_sig)
{
	loff_t pos = pos_from_hilo(pos_h, pos_l);
	struct fd f;
	ssize_t ret = -EBADF;
	unsigned long oldrsp;
	ktime_t start, end;

	if (pos < 0)
		return -EINVAL;

	f = fdget(fd);
	if (f.file) {
		start = ktime_get();

		loff_t prev_pos = pos;
		ret = -ESPIPE;
		if (f.file->f_mode & FMODE_PWRITE)
			ret = vfs_writev(f.file, vec, vlen, &pos);
		fdput(f);

		end = ktime_get();
		oldrsp = current_pt_regs()->sp;
		record_request_without_pc(fd, f.file, vlen, IO_PWRITEV, oldrsp, prev_pos, start, end, pc_sig);
	}

	if (ret > 0)
		add_wchar(current, ret);
	inc_syscw(current);
	return ret;
}






