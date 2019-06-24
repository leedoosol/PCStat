obj-m := pcadv.o 
pcadv-y := pcadvisor.o kernel_file_io.o
PWD = $(shell pwd)

all:
	make -C /lib/modules/3.16.43/build M=$(PWD) modules
clean:
	make -C /lib/modules/3.16.43/build M=$(PWD) clean 
