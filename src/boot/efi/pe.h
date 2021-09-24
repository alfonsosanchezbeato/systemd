/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <efidef.h>

#include "util.h"

struct DosFileHeader {
        UINT8   Magic[2];
        UINT16  LastSize;
        UINT16  nBlocks;
        UINT16  nReloc;
        UINT16  HdrSize;
        UINT16  MinAlloc;
        UINT16  MaxAlloc;
        UINT16  ss;
        UINT16  sp;
        UINT16  Checksum;
        UINT16  ip;
        UINT16  cs;
        UINT16  RelocPos;
        UINT16  nOverlay;
        UINT16  reserved[4];
        UINT16  OEMId;
        UINT16  OEMInfo;
        UINT16  reserved2[10];
        UINT32  ExeHeader;
} _packed_;

struct CoffFileHeader {
        UINT16  Machine;
        UINT16  NumberOfSections;
        UINT32  TimeDateStamp;
        UINT32  PointerToSymbolTable;
        UINT32  NumberOfSymbols;
        UINT16  SizeOfOptionalHeader;
        UINT16  Characteristics;
} _packed_;

struct PeOptionalHeader {
        UINT16 Magic;
        UINT8 MajorLinkerVersion;
        UINT8 MinorLinkerVersion;
        UINT32 SizeOfCode;
        UINT32 SizeOfInitializedData;
        UINT32 SizeOfUninitializedData;
        UINT32 AddressOfEntryPoint;
        UINT32 BaseOfCode;
        /* We don't need to define the rest of the fields from the PE specification */
} _packed_;

struct PeFileHeader {
        UINT8   Magic[4];
        struct CoffFileHeader FileHeader;
        struct PeOptionalHeader OptionalHeader;
} _packed_;

struct PeSectionHeader {
        UINT8   Name[8];
        UINT32  VirtualSize;
        UINT32  VirtualAddress;
        UINT32  SizeOfRawData;
        UINT32  PointerToRawData;
        UINT32  PointerToRelocations;
        UINT32  PointerToLinenumbers;
        UINT16  NumberOfRelocations;
        UINT16  NumberOfLinenumbers;
        UINT32  Characteristics;
} _packed_;

EFI_STATUS pe_memory_locate_sections(
                const CHAR8 *base,
                const CHAR8 **sections,
                UINTN *addrs,
                UINTN *sizes);

EFI_STATUS pe_file_locate_sections(
                EFI_FILE *dir,
                const CHAR16 *path,
                const CHAR8 **sections,
                UINTN *offsets,
                UINTN *sizes);
