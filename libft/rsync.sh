#!/bin/bash
LIBFTDIR="$(dirname "$BASH_SOURCE")"
rsync -av \
	$LIBFTDIR/.gitignore \
	$LIBFTDIR/Makefile \
	$LIBFTDIR/include \
	$LIBFTDIR/ft_*.c \
	$LIBFTDIR/ft_printf \
	$LIBFTDIR/ft_argparse \
	$LIBFTDIR/ft_error_functions \
	$LIBFTDIR/get_next_line \
	$1
