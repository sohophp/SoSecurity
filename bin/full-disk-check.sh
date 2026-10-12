#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
task_runtime=${1:-php}
task_disk_dir=$(mktemp -d /tmp/sosecurity-full-disk.XXXXXXXX)
task_mounted=0
cleanup() {
    if [[ "$task_mounted" == 1 ]]; then sudo -n umount "$task_disk_dir"; fi
    rmdir "$task_disk_dir"
}
trap cleanup EXIT
sudo -n mount -t tmpfs -o "size=16k,mode=0700,uid=$(id -u),gid=$(id -g)" tmpfs "$task_disk_dir"
task_mounted=1
SOSECURITY_TEST_FULL_DISK="$task_disk_dir" "$task_runtime" tests/full-disk.php
