/**
 * @file include/fileformat/fileformat.h
 * @brief Interface to fileformat library.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEFORMAT_FILEFORMATL_H
#define FILEFORMAT_FILEFORMATL_H

#include "fileformat/file_format/coff/coff_format.h"
#include "fileformat/file_format/elf/elf_format.h"
#include "fileformat/file_format/intel_hex/intel_hex_format.h"
#include "fileformat/file_format/macho/macho_format.h"
#include "fileformat/file_format/pe/pe_format.h"
#include "fileformat/file_format/raw_data/raw_data_format.h"
#include "fileformat/format_factory.h"
#include "fileformat/utils/format_detection.h"

#endif
