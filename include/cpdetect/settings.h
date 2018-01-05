/**
 * @file include/cpdetec/settings.h
 * @brief Settings for compiler detection.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef CPDETECT_SETTINGS_H
#define CPDETECT_SETTINGS_H

#include <string>
#include <vector>

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

} // namespace cpdetect

#endif
