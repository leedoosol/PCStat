/**
 * pcadvisor: automated advisor per configured PCs
 * author: Yongseok Jin
 *
 * README:
 *		some functions' symbols are not exported,
 *		so you have to export those by yourself in kernel.
 *
 *		in version 3.16.43:
 *			lru_add_drain(): mm/swap.c, 820
 * 			lru_add_drain_all(): mm/swap.c, 833
 *			__filemap_fdatawrite_range(): mm/filemap.c, 333
 *			force_page_cache_readahead(): mm/readahead.c, 210
 *			sb_is_blkdev_sb(): fs/block_dev.c, 659
 */

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
#include <linux/swap.h>

#include "pc_table.h"

#define HASH_TABLE_SIZE 32768

#define TRUE 1
#define FALSE 0
#define ADDRESS_UNIT 8
#define NUM_RET_ADDR_THRESHOLD 5
#define LOCK_ENABLE

#ifdef LOCK_ENABLE
spinlock_t g_lock_sys; /* global lock for system call */
#endif

/* table for pc configuration */
pc_table* table;


/**
 * calculates current PC signature.
 */
static unsigned long calculate_pc_sig(unsigned long oldrsp)
{	
	struct mm_struct *mm;
	unsigned long stk_top, stk_bot, stk_cur, value, num_addr = 0;
	unsigned long pc_sig = 0;
	struct vm_area_struct *vma;

#ifdef LOCK_ENABLE
	spin_lock(&g_lock_sys);
#endif

	/* get the addresses of code segment from stack. */
	mm = current->mm;
	stk_top = oldrsp; /* recent user-level RSP(ESP) is at the top of stack */
	vma = find_vma(mm, stk_top);
	stk_bot = vma->vm_end;

	for(stk_cur = stk_top; stk_cur < stk_bot; stk_cur += ADDRESS_UNIT) {
		if(!copy_from_user(&value, stk_cur, ADDRESS_UNIT)) {
			/* check if the address stored in stack is inside the code segment */
			if(mm->start_code < value && value < mm->end_code) {
				/* add up the PC value. */
				pc_sig += value - mm->start_code;
	
				num_addr++;
				if(num_addr > NUM_RET_ADDR_THRESHOLD)
					break;
			}
		}
	}

#ifdef LOCK_ENABLE
	spin_unlock(&g_lock_sys);
#endif

	return pc_sig;
}

/**
 * setup pc table by configuration.
 */
static void setup_pc_table(void)
{
	struct file* filp;
	char buf[100];
	unsigned long pc_sig;
	char mode1, mode2;
	int i;
	char* buf_ptr;

	table = create_pc_table (HASH_TABLE_SIZE);

	filp = file_open ("/tmp/pc_conf.ini", O_RDONLY, 0666);

	while (kernel_fgets(buf, filp) != 0) {
		buf_ptr = buf;
		i = 0;
		pc_sig = 0;
		mode1 = 0;
		mode2 = 0;

		/* tokenize string, get pc signature and optimization modes. */
		while (1) {
			if (buf[i] == ' ') {
				buf[i] = 0;

				if (pc_sig == 0) {
					pc_sig = simple_strtol(buf_ptr, NULL, 10);
				}
				else if (mode1 == 0) {
					mode1 = simple_strtol(buf_ptr, NULL, 10);
				}
				else {
					mode2 = simple_strtol(buf_ptr, NULL, 10);
				}

				buf_ptr = buf + i + 1;
			}
			else if (buf[i] == 0) {
				if (mode1 == 0) {
					mode1 = simple_strtol(buf_ptr, NULL, 10);
				}
				else {
					mode2 = simple_strtol(buf_ptr, NULL, 10);
				}
				break;
			}
			++i;
		}

		/* put entry into table. */
		put_entry (table, pc_sig, mode1, mode2);
	}

	file_close (filp);
}

typedef int (*pre_advisor)(unsigned long, struct file*);
extern int set_pre_advisor (pre_advisor func);

static inline struct backing_dev_info *inode_to_bdi(struct inode *inode)
{
	struct super_block *sb = inode->i_sb;

	if (sb_is_blkdev_sb(sb))
		return inode->i_mapping->backing_dev_info;

	return sb->s_bdi;
}

/**
 * pre_advise: calculate PC,
 * apply post-optimization for SEQ and RAND,
 * return hint for DONTNEED, WILLNEED, or no further optimization.
 */
static int pcadvisor_pre_advise(unsigned long oldrsp, struct file* file)
{
	struct backing_dev_info* bdi;
	unsigned long pc_sig;
	pc_entry* entry;

	/* only capture I/O syscall from selected process */
	if(strcmp(current->comm, "db_bench") != 0)
		return 0;

	bdi = inode_to_bdi(file->f_mapping->host);

	/* calculate pc signature, find in table. */
	pc_sig = calculate_pc_sig (oldrsp);
	if ((entry = get_entry (table, pc_sig)) == NULL) {
		return 0; /* No-optimization */
	}

	/* set sequential/random according to the mode. */
	if (entry->mode1 == 1) { /* SEQUENTIAL */
		/* enlarge the limit of readahead size. */
//		file->f_ra.ra_pages = bdi->ra_pages * 2;
//		spin_lock (&file->f_lock);
//		file->f_mode &= ~FMODE_RANDOM;
//		spin_unlock (&file->f_lock);
	}
	else if (entry->mode1 == 2) { /* RANDOM */
		/* set file configuration to 'random'. */
		spin_lock (&file->f_lock);
		file->f_mode |= FMODE_RANDOM;
		spin_unlock (&file->f_lock);
	}
	else {
		/* mode1 must stand for WILLNEED/DONTNEED. */
		return entry->mode1;
	}

	/* mode2 can be 0(No-optimization), 3(DONTNEED), 4(WILLNEED). */
	return entry->mode2;
}

typedef void (*post_advisor)(int, struct file*, loff_t, unsigned int);
extern int set_post_advisor (post_advisor func);

/**
 * post_advise: advise according to the optimization code
 * for better buffer management. (DONTNEED, WILLNEED)
 */
static void pcadvisor_post_advise(int opt_code, struct file* file, loff_t offset, unsigned int len)
{
	struct inode* inode;
	struct address_space* mapping;
	pgoff_t start_index, end_index;
	unsigned long nrpages;
	loff_t endbyte;

	if (opt_code == 0) {
		return;
	}

	inode = file_inode(file);
	mapping = file->f_mapping;

	/* find the end byte offset */
	endbyte = (u64)offset + (u64)len;
	if (!len || endbyte < len) {
		endbyte = -1;
	}
	else {
		--endbyte; /* inclusive */
	}
	
	/* apply optimization */
	if (opt_code == 3) { /* DONTNEED */
		if (!bdi_write_congested (mapping->backing_dev_info)) {
			__filemap_fdatawrite_range (mapping, offset, endbyte, WB_SYNC_NONE);
		}

		/* First and last FULL page! Partial pages are deliberately
		 * preserved on the expectation that it is better to preserve
		 * needed memory than to discard unneeded memory.
		 */
		start_index = (offset + (PAGE_SIZE - 1)) >> PAGE_SHIFT;
		end_index = (endbyte >> PAGE_SHIFT);

		/* The page at end_index will be inclusively discarded according
		 * by invalidate_mapping_pages(), so subtracting 1 from
		 * end_index means we will skip the last page. But if endbyte
		 * is page aligned or is at the end of file, we should not skip
		 * that page - discarding the last page is safe enough.
		 */
		if ((endbyte & ~PAGE_MASK) != ~PAGE_MASK && endbyte != inode->i_size - 1) {
			/* First page is tricky as 0 - 1 = -1, but pgoff_t
			 * is unaligned, so the end_index >= start_index
			 * check below would be true and we will discard the whole
			 * file cache which is not what was asked.
			 */
			if (end_index == 0) {
				return;
			}
			--end_index;
		}

		if (end_index >= start_index) {
			unsigned long count;

			/*
			 * It's common to FADV_DONTNEED right after
			 * the read or write that instantiates the
			 * pages, in which case there will be some
			 * sitting on the local LRU cache. Try to
			 * avoid the expensive remote drain and the
			 * second cache tree walk below by flushing
			 * them out right away.
			 */
			lru_add_drain();
			count = invalidate_mapping_pages(mapping, start_index, end_index);

			/*
			 * If fewer pages were invalidated than expected then
			 * it is possible that some of the pages were on
			 * a per-cpu pagevec for a remote CPU. Drain all
			 * pagevecs and try again.
			 */
			if (count < (end_index - start_index + 1)) {
				lru_add_drain_all();
				invalidate_mapping_pages(mapping, start_index, end_index);
			}
		}
		//printk(KERN_INFO "[PCAdvisor] DONTNEED\n");
	}
	else if (opt_code == 4) { /* WILLNEED */
		start_index = offset >> PAGE_SHIFT;
		end_index = endbyte >> PAGE_SHIFT;

		/* careful about overflow on the +1 */
		nrpages = end_index - start_index + 1;
		if (!nrpages) {
			nrpages = ~0UL;
		}

		/* ignore return value. */
		force_page_cache_readahead (mapping, file, start_index, nrpages);
		//printk(KERN_INFO "[PCAdvisor] WILLNEED\n");
	}
}

/**
 * initializes pcadvisor.
 */
static int pcadvisor_init(void)
{
#ifdef LOCK_ENABLE
	spin_lock_init(&g_lock_sys);
#endif

	/* read configuration file and setup pc table */
	setup_pc_table ();

	/* enable PC optimization */
	set_post_advisor (pcadvisor_post_advise);
	set_pre_advisor (pcadvisor_pre_advise);

	printk(KERN_INFO "[PCAdvisor] init module\n");

	return 0;
}

/**
 * destroys pcadvisor.
 */
static void pcadvisor_exit(void)
{
	/* disable PC optimization */
	set_pre_advisor (NULL);
	set_post_advisor (NULL);

	/* destruct pc_table */
	destroy_pc_table (table);

	printk(KERN_INFO "[PCAdvisor] exit module\n");
}


module_init(pcadvisor_init);
module_exit(pcadvisor_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("ysjin");
MODULE_DESCRIPTION("test module");




