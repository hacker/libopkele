#!/bin/bash
eval bash autogen.bash $(./config.status --version | grep '^  with options "'|sed -e 's/^[^"]\+"//' -e 's/"$//') "$@"
