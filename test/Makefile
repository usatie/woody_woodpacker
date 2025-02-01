all:
	$(CC) -o empty empty.c
	$(CC) -o putc putc.c
	$(CC) -o hello hello.c

run: all
	../woody_woodpacker empty
	../woody_woodpacker putc
	../woody_woodpacker hello

clean:
	$(RM) empty putc hello

re: clean all
