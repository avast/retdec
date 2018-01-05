/**
* @file src/ctypesparser/ctypes_parser.cpp
* @brief Parser for C-types files.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "ctypes/context.h"
#include "ctypesparser/ctypes_parser.h"

namespace ctypesparser {

/**
* @brief Creates new C-types parser.
*/
CTypesParser::CTypesParser():
	context(std::make_shared<ctypes::Context>()) {}

/**
* @brief Creates new C-types parser.
*
* @param defaultBitWidth BitWidth used for types that are not in typeWidths.
*/
CTypesParser::CTypesParser(unsigned defaultBitWidth):
	context(std::make_shared<ctypes::Context>()),
	defaultBitWidth(defaultBitWidth) {}

} // namespace ctypesparser
