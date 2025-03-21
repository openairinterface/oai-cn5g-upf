#!/bin/sh

# Mount bpffs and debugfs if not present already
if [ $(/bin/mount | /bin/grep /sys/fs/bpf -c) -eq 0 ]; then
    /bin/mount bpffs /sys/fs/bpf -t bpf;
fi
if [ $(/bin/mount | /bin/grep debugfs -c) -eq 0 ]; then
    /bin/mount debugfs /sys/kernel/debug -t debugfs;
fi

exec "$@"