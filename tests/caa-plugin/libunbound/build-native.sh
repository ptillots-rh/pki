#!/bin/sh
# Copyright Red Hat, Inc.
# SPDX-License-Identifier: GPL-2.0-or-later
set -eu
module_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
repo_dir=$(CDPATH= cd -- "$module_dir/../../.." && pwd)
jdk_dir=${JAVA_HOME:-$(dirname "$(dirname "$(readlink -f "$(command -v javac)")")")}
mkdir -p "$module_dir/target/native"
${CC:-cc} -std=c11 -O2 -g -fPIC -shared -Wall -Wextra -Werror \
    -I"$jdk_dir/include" -I"$jdk_dir/include/linux" \
    $(pkg-config --cflags libunbound) \
    "$repo_dir/base/acme/caa-plugins/libunbound/src/main/native/libunbound_jni.c" \
    -Wl,-z,defs -o "$module_dir/target/native/libpki_acme_unbound.so" \
    $(pkg-config --libs libunbound)
