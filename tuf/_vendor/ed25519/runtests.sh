#!/bin/sh
set -e

python -u signfast.py < sign.input

if [[ $TEST == 'slow' ]]; then
    python -u sign.py < sign.input
fi
