#!/bin/bash

if (( $EUID != 0 )); then
    echo "Please run as root"
    exit
fi

SRC_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
DST_DIR=/usr/local/bin/

for filename in ${SRC_DIR}/build/bin/*; do
	[ -e "$filename" ] || continue
	echo "Uninstalling $(basename $filename)..."
	rm ${DST_DIR}/$(basename $filename)
done

