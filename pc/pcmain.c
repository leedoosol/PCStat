
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
#include  <linux/workqueue.h>
#include  <linux/slab.h>

// header for request, bio
#include  <linux/blkdev.h>

#include <linux/ktime.h>

typedef void (*FuncType)(unsigned int, struct file*, unsigned int, unsigned int, unsigned long, loff_t, ktime_t, ktime_t);
extern int set_record_syscall_pc (FuncType fn);

#define TRUE 1
#define FALSE 0
#define ADDRESS_UNIT 4
#define NUM_RET_ADDR_THRESHOLD 10
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
struct file* filpscall; /* syscall file pointer */

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
		value = ValueOf(stk_cur);

		/* check if the address stored in stack is inside the code segment */
		if(mm->start_code <= value && value <= mm->end_code) {
			/* store each PC to PC buffer */
			sprintf(pc_buf + pc_buf_idx, "%p ", (void*)(value - mm->start_code));
			pc_buf_idx = strlen(pc_buf);

			num_addr++;
			if(num_addr > NUM_RET_ADDR_THRESHOLD)
				break;
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
	//sprintf(buffer, "[PC%d] cmd:%s, d_iname:%s, pc:%s, timestamp:%lld, latency: %lld\n",
	//	gsyscnt++, current->comm, path, pc_buf, start.tv64, end.tv64 - start.tv64);
	sprintf(buffer, "%lld\t%lld\t%s\t%u\t%lld\t%u\t%s\n", start.tv64, end.tv64 - start.tv64, path, type, pos, count, pc_buf);

	/* free the temporary page */
	free_page((unsigned long)tmp_page);

#ifdef PRINT_SYSCALL
	/* write I/O log to file */
	file_write(buffer, strlen(buffer), filpscall);
#endif

#ifdef LOCK_ENABLE
	spin_unlock(&g_lock_sys);
#endif
}

/**
 * initialize PC module
 */
static int pcmain_init(void) {
#ifdef LOCK_ENABLE
	spin_lock_init(&g_lock_sys);
#endif

#ifdef PRINT_SYSCALL
	strcpy(file_namepc, "/tmp/pcscall");
	if((filpscall = file_open(file_namepc, O_RDWR | O_LARGEFILE| O_CREAT | O_TRUNC, 0666)) == NULL)
	{
		printk (KERN_INFO "file_open_error (%s)\n", file_namepc);
		return 1;
	}
#endif

	set_record_syscall_pc (&record_pc_fn);

	printk(KERN_INFO "[PC] init module\n");
	return 0;
}

/**
 * destroy PC module
 */
static void pcmain_exit(void) {
	set_record_syscall_pc (NULL);

#ifdef PRINT_SYSCALL
	file_close(filpscall);
#endif
	printk(KERN_INFO "[PC] exit module\n");
}



module_init(pcmain_init);
module_exit(pcmain_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("tjkim, ysjin");
MODULE_DESCRIPTION("Test module");
