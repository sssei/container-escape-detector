obj-m += ns-detect.o mount-escape-detector.o

PWD := $(CURDIR)

all:
	make -C	/lib/modules/6.8.12+/build M=$(PWD) EXTRA_CFLAGS='-save-temps' modules 

clean:
	make -C /lib/modules/6.8.12+/build M=$(PWD) clean 
