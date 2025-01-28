#!/bin/bash
# Clone testers
[ ! -d libft-tester-tokyo ] && git clone https://github.com/usatie/libft-tester-tokyo.git || echo "libft-teste-tokyo is already cloned."
[ ! -d ../libft-unit-test ] && git clone https://github.com/alelievr/libft-unit-test.git ../libft-unit-test || echo "libft-unit-test is already cloned."
[ ! -d libftTester ] && git clone https://github.com/Tripouille/libftTester.git || echo "libftTester is already cloned."

# Run tester
cp include/libft.h ./
make all

echo "Running libft-tester-tokyo..."
make -C libft-tester-tokyo norm
make -C libft-tester-tokyo
make -C libft-tester-tokyo bonus
make -C libft-tester-tokyo extra

echo "Running libft-unit-test..."
make -C ../libft-unit-test f

echo "Running libftTester..."
make -C libftTester a
make fclean

rm libft.h
