CC		= gcc
CFLAGS	= -Wall -g -D_GNU_SOURCE -fPIC
PROGS	= sandbox.so

all: $(PROGS)

%.o: %.c
	$(CC) -c $< $(CFLAGS)

sandbox.so: sandbox.o
	$(CC) -o $@ -shared $^ 

example1:
	./launcher ./sandbox.so config.txt cat /etc/passwd

example2:
	./launcher ./sandbox.so config.txt cat /etc/hosts

example3:
	./launcher ./sandbox.so config.txt cat /etc/ssl/certs/Amazon_Root_CA_1.pem

example5:
	./launcher ./sandbox.so config.txt wget http://google.com -t 1

example6:
	./launcher ./sandbox.so config.txt wget https://www.nycu.edu.tw -t 1

example7:
	./launcher ./sandbox.so config.txt wget http://www.google.com -q -t 1

example8:
	./launcher ./sandbox.so config.txt python3 -c 'import os;os.system("wget http://www.google.com -q -t 1")'

cleanup:
	rm -f *.o

clean:
	rm -f $(PROGS) *.o