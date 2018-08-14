/**
 * @file include/retdec/cpdetect/cpdetect.h
 * @brief Interface to cpdetectl library.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CPDETECT_CPDETECTL_H
#define RETDEC_CPDETECT_CPDETECTL_H

#include "retdec/cpdetect/compiler_detector/coff_compiler.h"
#include "retdec/cpdetect/compiler_detector/elf_compiler.h"
#include "retdec/cpdetect/compiler_detector/intel_hex_compiler.h"
#include "retdec/cpdetect/compiler_detector/macho_compiler.h"
#include "retdec/cpdetect/compiler_detector/pe_compiler.h"
#include "retdec/cpdetect/compiler_detector/raw_data_compiler.h"
#include "retdec/cpdetect/compiler_factory.h"
#include "retdec/cpdetect/errors.h"

#endif
