all:
	$(CC) -o empty empty.c
	$(CC) -o putc putc.c
	$(CC) -o hello hello.c

run: all
	../woody_woodpacker empty
	./empty.packed
	@rm empty.packed
	@echo "---------------------------------------"
	../woody_woodpacker putc
	./putc.packed
	@rm putc.packed
	@echo "---------------------------------------"
	../woody_woodpacker hello
	./hello.packed
	@rm hello.packed
	@echo "---------------------------------------"
	../woody_woodpacker ../woody_woodpacker
	../woody_woodpacker.packed empty
	./empty.packed
	@rm empty.packed
	@echo "---------------------------------------"
	../woody_woodpacker.packed putc
	./putc.packed
	@rm putc.packed
	@echo "---------------------------------------"
	../woody_woodpacker.packed hello
	./hello.packed
	@rm hello.packed
	@echo "---------------------------------------"

clean:
	$(RM) empty putc hello

re: clean all
