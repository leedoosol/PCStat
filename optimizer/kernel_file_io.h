struct file* file_open(const char* file_name, int flags, int mode);
void file_close(struct file* file);
uint64_t file_seek(struct file* filp, uint64_t offset, int whence);
int file_read(
		char* buf,
		int len,
		struct file *filp);
int file_write(
		char* buf,
		int len,
		struct file *filp);
int kernel_fgets(char* buf, struct file *filp);
