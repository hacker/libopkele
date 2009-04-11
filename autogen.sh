#!/bin/sh
WANT_AUTOMAKE=1.8
export WANT_AUTOMAKE
libtoolize -f \
&& aclocal -I aclocal.d \
&& autoheader \
&& automake -a \
&& autoconf \
&& ./configure "$@"
