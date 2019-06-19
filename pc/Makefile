obj-m := pcm.o 
pcm-y := pcmain.o kernel_file_io.o
PWD = $(shell pwd)

all:
	make -C /lib/modules/3.16.43/build M=$(PWD) modules
clean:
	make -C /lib/modules/3.16.43/build M=$(PWD) clean 
