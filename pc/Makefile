obj-m := pcm.o 
pcm-y := pcmain.o kernel_file_io.o
PWD = $(shell pwd)

all:
	make -C /lib/modules/4.5.0/build M=$(PWD) modules
clean:
	make -C /lib/modules/4.5.0/build M=$(PWD) clean 
