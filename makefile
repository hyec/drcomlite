CROSS_COMPILE ?= 

.PHONY = all clean

all: clean drcom

drcom: main.o md5.o
	$(CROSS_COMPILE)gcc main.o md5.o -o drcom

main.o: main.c md5.h
	$(CROSS_COMPILE)gcc -c main.c

md5.o: md5.c md5.h
	$(CROSS_COMPILE)gcc -c md5.c

clean:
	@rm -f drcom *.o
