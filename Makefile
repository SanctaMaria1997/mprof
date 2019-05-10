all: mprof libmprof.so manpage depend

mprof: mprof.o mprof_util.o elf_util.o args.o
	cc -g mprof.o mprof_util.o elf_util.o args.o -o mprof
mprof.o: mprof.c
	cc -g -c -DFREEBSD mprof.c -o mprof.o
args.o: args.c
	cc -g -c args.c -o args.o
libmprof.so: libmprof.o dwarfy.o mprof_util.o elf_util.o
	cc -g -shared -fPIC libmprof.o dwarfy.o mprof_util.o elf_util.o -o libmprof.so -lm
libmprof.o: libmprof.c
	cc -g -c -DFREEBSD -fPIC libmprof.c -o libmprof.o
dwarfy.o: dwarfy.c
	cc -g -c -DFREEBSD -fPIC dwarfy.c -o dwarfy.o
mprof_util.o: mprof_util.c
	cc -g -c -fPIC mprof_util.c -o mprof_util.o
elf_util.o: elf_util.c
	cc -g -c -fPIC elf_util.c -o elf_util.o
dwarfy_test: dwarfy_test.c
	cc -g dwarfy_test.c dwarfy.o -o dwarfy_test
example: fish.o hamster.o libdugong.so
	cc -g fish.o hamster.o -o example -L. -ldugong
libdugong.so: dugong.o
	cc -g -shared -fPIC dugong.o -o libdugong.so
fish.o: fish.c
	cc -c -g fish.c -o fish.o
hamster.o: hamster.c
	cc -c -g hamster.c -o hamster.o
dugong.o: dugong.c
	cc -c -g -fPIC dugong.c -o dugong.o

manpage: mprof.1
	gzip -f -k mprof.1
install:
	cp mprof /usr/local/bin
	cp libmprof.so /usr/local/lib
	cp mprof.1.gz /usr/share/man/man1/
install-example:
	cp libdugong.so /usr/local/lib
depend:
	cc -E -MM *.c > .depend
clean:
	@rm *.o *.so mprof mprof.1.gz
