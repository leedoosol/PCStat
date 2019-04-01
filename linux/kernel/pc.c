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

asmlinkage unsigned long sys_get_pc()
{
	char buf[256];
	int buf_idx = 0;
	struct mm_struct *mm;
	unsigned long stk_top, stk_bot, stk_cur, value, num_addr = 0;
	struct vm_area_struct *vma;
	unsigned long sp;
	unsigned long sum_pc = 0;
	struct file* pc_fp;

	memset(buf, 0x00, sizeof(char) * 256);

	sp = current_pt_regs()->sp;

	/* get the addresses of code segment from stack. */
	mm = current->mm;
	stk_top = sp;
	vma = find_vma(mm, stk_top);
	stk_bot = vma->vm_end;

	for (stk_cur = stk_top; stk_cur < stk_bot; stk_cur += ADDRESS_UNIT) {
		value = ValueOf(stk_cur);

		/* check if the address stored in stack is inside the code segment */
		if (mm->start_code <= value && value <= mm->end_code) {
			/* store each PC into buffer */
			sprintf(buf + buf_idx, "%p ", (void *)(value - mm->start_code));
			buf_idx = strlen(buf);

			/* add PC up */
			sum_pc += value - mm->start_code;

			num_addr++;
			if (num_addr > NUM_RET_ADDR_THRESHOLD)
				break;
		}
	}

	if (num_addr != 0) {
		/* add sum of pc to buffer */
		sprintf(buf + buf_idx, "\t%lx", value);
		
		/* print pc information to file */
		if ((pc_fp = file_open("/tmp/pc_syscall.log",
								O_RDWR | O_LARGEFILE | O_CREAT | O_TRUNC, 0666)) == NULL) {
			printk (KERN_INFO "[PC_syscall] file open error (/tmp/pc_syscall.log)\n");
			return 0;
		}

		file_write(buf, strlen(buf), pc_fp);
		file_close(pc_fp);
	}

	return sum_pc;
}























