/**
 * @file include/retdec/cpdetect/settings.h
 * @brief Settings for compiler detection.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CPDETECT_SETTINGS_H
#define RETDEC_CPDETECT_SETTINGS_H

#include <set>
#include <string>
#include <vector>

namespace retdec {
namespace cpdetect {

/*
 * 512 kiB
 */
const std::size_t LIGHTWEIGHT_FILE_SCAN_AREA = 0x80000;

const std::size_t EP_BYTES_SIZE = 50;

const std::set<std::string> EXTERNAL_DATABASE_SUFFIXES =
{
	".yar",
	".yara"
};

const std::string YARA_RULES_PATH = "../share/retdec/support/generic/yara_patterns/tools/";

} // namespace cpdetect
} // namespace retdec

#endif
