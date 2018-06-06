/**
* @file include/retdec/bin2llvmir/utils/capstone.h
* @brief Capstone utilities.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_UTILS_CAPSTONE_H
#define RETDEC_BIN2LLVMIR_UTILS_CAPSTONE_H

#include <capstone/capstone.h>

#include "retdec/config/config.h"

namespace retdec {
namespace bin2llvmir {
namespace capstone_utils {

std::string mode2string(const config::Architecture& arch, cs_mode m);

} // namespace capstone_utils
} // namespace bin2llvmir
} // namespace retdec

#endif
