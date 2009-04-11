#!/bin/bash
eval sh autogen.sh $(./config.status --version | grep '^  with options "'|sed -e 's/^[^"]\+"//' -e 's/"$//') "$@"
