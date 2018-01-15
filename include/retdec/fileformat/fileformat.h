/**
 * @file include/retdec/fileformat/fileformat.h
 * @brief Interface to fileformat library.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_FILEFORMATL_H
#define RETDEC_FILEFORMAT_FILEFORMATL_H

#include "retdec/fileformat/file_format/coff/coff_format.h"
#include "retdec/fileformat/file_format/elf/elf_format.h"
#include "retdec/fileformat/file_format/intel_hex/intel_hex_format.h"
#include "retdec/fileformat/file_format/macho/macho_format.h"
#include "retdec/fileformat/file_format/pe/pe_format.h"
#include "retdec/fileformat/file_format/raw_data/raw_data_format.h"
#include "retdec/fileformat/format_factory.h"
#include "retdec/fileformat/utils/format_detection.h"

#endif
