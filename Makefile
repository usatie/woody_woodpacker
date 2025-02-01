NAME=woody_woodpacker
CC=cc
CFLAGS=-Wall -Werror -Wextra
SRCS=$(wildcard src/*.c)
OBJS=$(SRCS:%.c=%.o)
INC=-I./include -I./libft/include
LIBFT=libft/libft.a
LOADER=src/loader

all: $(NAME)

$(NAME): $(OBJS) $(LOADER) $(LIBFT)
	$(CC) -o $(NAME) $(OBJS) $(CFLAGS) $(LIBFT)

%.o: %.c
	$(CC) -c $< -o $@ $(CFLAGS) $(INC)

clean:
	$(RM) $(OBJS)

fclean: clean
	$(RM) $(NAME)

re: fclean all

dbuild:
	docker buildx build --platform=linux/amd64 -t amd64-woody-woodpacker .

drun:
	docker run --rm -it --platform=linux/amd64 amd64-woody-woodpacker bash

test: all
	$(MAKE) run -C test

$(LIBFT):
	$(MAKE) -C libft

$(LOADER): $(LOADER).nasm
	nasm $(LOADER).nasm

.PHONY: all clean fclean re dbuild drun test
