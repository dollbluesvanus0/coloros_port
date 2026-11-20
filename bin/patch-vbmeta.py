#!/usr/bin/env python

import os
import sys

# Magic for the vbmeta image header
AVB_MAGIC = b"AVB0"
AVB_MAGIC_LEN = 4

# Information about the verification flags
FLAGS_OFFSET = 123
FLAGS_TO_SET = b'\x03'

if __name__ == "__main__":

    # if a correct argument is not provided
    if len(sys.argv) != 2:
        sys.exit(f"Usage: python ./{os.path.basename(__file__)} <vbmeta-image>")

    # try reading the file with read/write to make sure it exists
    FILE = sys.argv[1]

    try:
        fd = os.open(FILE, os.O_RDWR | getattr(os, "O_BINARY", 0))
    except OSError:
        sys.exit(f"Error reading file: {FILE}\nFile not modified. Exiting...")

    # making sure it's a vbmeta image by reading the magic bytes at the start of the file
    magic = os.read(fd, AVB_MAGIC_LEN)

    if magic != AVB_MAGIC:
        os.close(fd)
        sys.exit("Error: The provided image is not a valid vbmeta image.\nFile not modified. Exiting...")

    try:
        if os.fstat(fd).st_size < FLAGS_OFFSET + len(FLAGS_TO_SET):
            os.close(fd)
            sys.exit("Error: The provided image is too small to be a valid vbmeta image.\nFile not modified. Exiting...")
        # set the disable-verity and disable-verification flags at offset 123
        os.lseek(fd, FLAGS_OFFSET, os.SEEK_SET)
        os.write(fd, FLAGS_TO_SET)
    except OSError:
        os.close(fd)
        sys.exit("Error: Failed when patching the vbmeta image.\nExiting...")

    # end of program
    os.close(fd)
    print("Patching successful.")