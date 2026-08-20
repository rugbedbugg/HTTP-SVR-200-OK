#!/bin/bash

set -euo pipefail

if [ -z "${1:-}" ]; then
	echo "Usage: ./build.sh <output-name>"
	exit 1
fi

name="$1"
gcc -nostdlib -no-pie -ffreestanding -fno-builtin -fno-stack-protector -o "$name" src/*.s src/*.c

echo "[+] Built executable \"$name\" using GCC."
echo "[!] Run \`./$name\` to execute and \`echo \$?\` to verify success."
