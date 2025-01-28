#!/bin/bash
# Clone testers
[ ! -d libft-tester-tokyo ] && git clone https://github.com/usatie/libft-tester-tokyo.git || echo "libft-teste-tokyo is already cloned."
[ ! -d printf-tester-tokyo ] && git clone https://github.com/usatie/printf-tester-tokyo.git || echo "printf-tester-tokyo is already cloned."
[ ! -d gnl-tester-tokyo ] && git clone https://github.com/usatie/gnl-tester-tokyo.git || echo "gnl-tester-tokyo is already cloned."

# Run tester
cp include/libft.h ./
make all
echo "Running libft-tester-tokyo..."
make -C libft-tester-tokyo norm
make -C libft-tester-tokyo
make -C libft-tester-tokyo bonus
make -C libft-tester-tokyo extra

#echo "Running libft-unit-test..."
#make -C libft-unit-test
#
#echo "Running libftTester..."
#make -C libftTester

rm libft.h

echo "Running printf-tester-tokyo..."
make -C printf-tester-tokyo FT_PRINTF=../libft.a

echo "Running gnl-tester-tokyo..."
make -C gnl-tester-tokyo M_SRCS="../get_next_line/get_next_line.c ../ft_strlcpy.c ../ft_strlen.c" INCS="../include -I ./includes" m
