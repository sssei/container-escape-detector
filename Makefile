obj-m += ns-detect.o mount-escape-detector.o

PWD := $(CURDIR)

all:
	make -C	/lib/modules/5.6.0-rc1/build M=$(PWD) modules 

clean:
	make -C /lib/modules/5.6.0-rc1/build M=$(PWD) clean 
