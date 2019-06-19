
// headers for kernel module
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>

// headers for process info
#include <asm-generic/current.h>
#include <linux/sched.h>
#include <linux/mm_types.h>
#include <linux/mm.h>

// header for struct file & inode
#include <linux/fs.h>

// header for spinlock
#include <asm/spinlock.h>

// header for pt_regs
#include <asm/uaccess.h>

// headers for file write
#include "kernel_file_io.h"
// header for workqueue
#include <linux/workqueue.h>
#include <linux/slab.h>
#include <linux/stat.h>
#include <linux/uio.h>

// header for request, bio
#include  <linux/blkdev.h>

#include <linux/unistd.h>
#include <linux/errno.h>
#include <linux/sched.h>
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

#include <asm/processor.h>
#include <asm/unistd.h>
#include <asm/percpu.h>
#include <asm/syscall.h>
#include <asm/ptrace.h>
#include <linux/ktime.h>

typedef void (*FuncType)(unsigned int, struct file*, unsigned int, unsigned int, unsigned long, loff_t, ktime_t, ktime_t);
extern int set_record_syscall_pc (FuncType fn);

//typedef void (*PCFuncType)(unsigned int, struct file*, unsigned int, unsigned int, unsigned long, loff_t, ktime_t, ktime_t, long);
//extern int set_record_syscall (PCFuncType fn);

//typedef unsigned long (*PCFunc)(void);
//extern int set_record_pc (PCFunc fn);

#define TRUE 1
#define FALSE 0
#define ADDRESS_UNIT 8
#define NUM_RET_ADDR_THRESHOLD 5
#define ValueOf(a) (*((unsigned long *) (a)))

#define PRINT_SYSCALL

#define LOCK_ENABLE

#ifdef LOCK_ENABLE
spinlock_t g_lock_sys; /* global lock for system call */
#endif

#define BUF_LEN 512
char buffer[BUF_LEN]; /* buffer for each log */

int gsyscnt = 0; /* global syscall count */
char file_namepc[128]; /* file name buffer */
struct file* io_syscall_fp; /* syscall file pointer */
struct file* pc_syscall_fp;

/**
 * record each PC's I/O information to log file
 */
void record_pc_fn(unsigned int fd, struct file *filp, unsigned int count, unsigned int type,
		unsigned long oldrsp, loff_t pos, ktime_t start, ktime_t end) {	
	char pc_buf[256]; /* buffer for pc addresses */
	int pc_buf_idx = 0;
	struct mm_struct *mm;
	unsigned long stk_top, stk_bot, stk_cur, value, num_addr = 0;
	struct vm_area_struct *vma;
	char *tmp_page, *path;

	/*
	if(strcmp(current->comm, "pc_test") != 0)
		return ;

	if(strcmp(current->comm, "bonnie++") != 0)
		return ;
	*/

	/* only record I/O information for certain process */
	if(strcmp(current->comm, "pc_test") != 0)
		return;

	/* skip if the I/O size is 0 */
	if(count == 0)
		return;

#ifdef LOCK_ENABLE
	spin_lock(&g_lock_sys);
#endif

	/* get the addresses of code segment from stack. */
	mm = current->mm;
	stk_top = oldrsp; /* recent user-level RSP(ESP) is at the top of stack */
	vma = find_vma(mm, stk_top);
	stk_bot = vma->vm_end;

	for(stk_cur = stk_top; stk_cur < stk_bot; stk_cur += ADDRESS_UNIT) {
		//value = ValueOf(stk_cur);
		if(!copy_from_user(&value, stk_cur, ADDRESS_UNIT)) {
			/* check if the address stored in stack is inside the code segment */
			if(mm->start_code < value && value < mm->end_code) {
				/* store each PC to PC buffer */
				sprintf(pc_buf + pc_buf_idx, "%p ", (void*)(value - mm->start_code));
				pc_buf_idx = strlen(pc_buf);
	
				num_addr++;
				if(num_addr > NUM_RET_ADDR_THRESHOLD)
					break;
			}
		}
	}

	if(num_addr == 0) {
#ifdef LOCK_ENABLE
		spin_unlock(&g_lock_sys);
#endif
		return;
	}
	
	/* get full path of file */
	tmp_page = (char*)__get_free_page(GFP_TEMPORARY);
	path = d_path(&filp->f_path, tmp_page, PAGE_SIZE);

	/* store the information of given PC's I/O */
	sprintf(buffer, "%lld\t%lld\t%s\t%u\t%lld\t%u\t%s\n", start.tv64, end.tv64 - start.tv64, path, type, pos, count, pc_buf);

	/* free the temporary page */
	free_page((unsigned long)tmp_page);

#ifdef PRINT_SYSCALL
	/* write I/O log to file */
	file_write(buffer, strlen(buffer), io_syscall_fp);
#endif

#ifdef LOCK_ENABLE
	spin_unlock(&g_lock_sys);
#endif
}

/**
 * record each PC's I/O information to log file - without PC calculation
 *
void record_syscall_fn(unsigned int fd, struct file *filp, unsigned int count, unsigned int type,
		unsigned long oldrsp, loff_t pos, ktime_t start, ktime_t end, long pc_sig) {	
	char *tmp_page, *path;

	*
	if(strcmp(current->comm, "pc_test") != 0)
		return ;

	if(strcmp(current->comm, "bonnie++") != 0)
		return ;
	*

	* only record I/O information for certain process *
	if(strcmp(current->comm, "pc_test") != 0)
		return;

	* skip if the I/O size is 0 *
	if(count == 0)
		return;

#ifdef LOCK_ENABLE
	spin_lock(&g_lock_sys);
#endif

	* get full path of file *
	tmp_page = (char*)__get_free_page(GFP_TEMPORARY);
	path = d_path(&filp->f_path, tmp_page, PAGE_SIZE);

	* store the information of given PC's I/O *
	sprintf(buffer, "%lld\t%lld\t%s\t%u\t%lld\t%u\tPC_SIG %lx\n", start.tv64, end.tv64 - start.tv64, path, type, pos, count, pc_sig);

	* free the temporary page *
	free_page((unsigned long)tmp_page);

#ifdef PRINT_SYSCALL
	* write I/O log to file *
	file_write(buffer, strlen(buffer), io_syscall_fp);
#endif

#ifdef LOCK_ENABLE
	spin_unlock(&g_lock_sys);
#endif
}

unsigned long pc_syscall_fn(void) {
	char buf[256];
	int buf_idx = 0;
	struct mm_struct *mm;
	unsigned long stk_top, stk_bot, stk_cur, value, num_addr = 0;
	struct vm_area_struct *vma;
	unsigned long sp;
	unsigned long sum_pc = 0;

	memset(buf, 0x00, sizeof(char) * 256);

	sp = current_pt_regs()->sp;

	* get the addresses of code segment from stack. *
	mm = current->mm;
	stk_top = sp;
	vma = find_vma(mm, stk_top);
	stk_bot = vma->vm_end;

	for (stk_cur = stk_top; stk_cur < stk_bot; stk_cur += ADDRESS_UNIT) {
		value = ValueOf(stk_cur);

		* check if the address stored in stack is inside the code segment *
		if (mm->start_code <= value && value <= mm->end_code) {
			* store each PC into buffer *
			sprintf(buf + buf_idx, "%p ", (void *)(value - mm->start_code));
			buf_idx = strlen(buf);

			* add PC up *
			sum_pc += value - mm->start_code;

			num_addr++;
			if (num_addr > NUM_RET_ADDR_THRESHOLD)
				break;
		}
	}

	if (num_addr != 0) {
		* add sum of pc to buffer *
		sprintf(buf + buf_idx, "\t%lx\n", sum_pc);
		
		file_write(buf, strlen(buf), pc_syscall_fp);
	}

	return sum_pc;
}*/

/**
 * initialize PC module
 */
static int pcmain_init(void) {
#ifdef LOCK_ENABLE
	spin_lock_init(&g_lock_sys);
#endif

#ifdef PRINT_SYSCALL
	strcpy(file_namepc, "/tmp/io_syscall.log");
	if((io_syscall_fp = file_open(file_namepc, O_RDWR | O_LARGEFILE| O_CREAT | O_TRUNC, 0666)) == NULL)
	{
		printk (KERN_INFO "[I/O syscall] file_open_error (%s)\n", file_namepc);
		return 1;
	}

//	if((pc_syscall_fp = file_open("/tmp/pc_syscall.log", O_RDWR | O_LARGEFILE | O_CREAT | O_TRUNC, 0666)) == NULL)
//	{
//		printk (KERN_INFO "[PC syscall] file open error(/tmp/pc_syscall.log)\n");
//		return 1;
//	}
#endif

	set_record_syscall_pc (&record_pc_fn);
//	set_record_syscall(&record_syscall_fn);

//	set_record_pc(&pc_syscall_fn);

	printk(KERN_INFO "[PC] init module\n");
	return 0;
}

/**
 * destroy PC module
 */
static void pcmain_exit(void) {
	set_record_syscall_pc (NULL);
//	set_record_syscall(NULL);

//	set_record_pc(NULL);

#ifdef PRINT_SYSCALL
	file_close(io_syscall_fp);
	file_close(pc_syscall_fp);
#endif
	printk(KERN_INFO "[PC] exit module\n");
}



module_init(pcmain_init);
module_exit(pcmain_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("tjkim, ysjin");
MODULE_DESCRIPTION("Test module");
