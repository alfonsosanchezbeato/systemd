/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/* See linux Documentation/arm64/booting.txt */
struct arm64_kernel_header {
        UINT32 code0;		/* Executable code */
        UINT32 code1;		/* Executable code */
        UINT64 text_offset;     /* Image load offset, little endian */
        UINT64 image_size;	/* Effective Image size, little endian */
        UINT64 flags;		/* kernel flags, little endian */
        UINT64 res2;		/* reserved */
        UINT64 res3;		/* reserved */
        UINT64 res4;		/* reserved */
        UINT32 magic;		/* Magic number, little endian, "ARM\x64" */
        UINT32 hdr_offset;	/* Offset of PE/COFF header */
} __attribute__((packed));
