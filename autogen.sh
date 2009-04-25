#!/bin/sh
tool_libtoolize="$(type -P glibtoolize || type -P libtoolize)"
if test -z "$tool_libtoolize" ; then
 echo "Failed to find libtoolize." ; exit 1;
fi
   "$tool_libtoolize" -f \
&& aclocal -I aclocal.d \
&& autoheader \
&& automake -a \
&& autoconf \
&& ./configure "$@"
