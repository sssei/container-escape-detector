obj-m += detect.o

PWD := $(CURDIR)

all:
	make -C	/lib/modules/6.8.12+/build M=$(PWD) modules 

clean:
	make -C /lib/modules/6.8.12+/build M=$(PWD) clean 
