#!/bin/bash

OUT=$(./$1)
RET=$?

if [ -n "$OUT" ]; then
    echo "$OUT"
fi
if [ $RET -ne 0 ]; then
    echo "$1 failed with return value $RET"
    exit
fi

echo "$1 passed with return value $RET"
