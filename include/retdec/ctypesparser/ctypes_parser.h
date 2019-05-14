/**
* @file include/retdec/ctypesparser/ctypes_parser.h
* @brief Parser for C-types.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_CTYPESPARSER_CTYPES_PARSER_H
#define RETDEC_CTYPESPARSER_CTYPES_PARSER_H

#include <map>
#include <memory>
#include <string>

#include "retdec/ctypes/ctypes.h"
#include "retdec/ctypesparser/exceptions.h"

namespace retdec {
namespace ctypesparser {

/**
* @brief A base class for parsing to C-types.
*
*/
class CTypesParser
{
	public:
		/// Set container for C-types' bit width.
		using TypeWidths = std::map<std::string, unsigned>;
		/// Set container for C-types' signedness.
		using TypeSignedness = std::map<std::string, ctypes::IntegralType::Signess>;

	public:
		virtual ~CTypesParser() = default;

	protected:
		CTypesParser();
		CTypesParser(unsigned defaultBitWidth);

	protected:
		/// Container for already parsed functions, types.
		std::shared_ptr<retdec::ctypes::Context> context;
		/// C-types' bit widths.
		TypeWidths typeWidths;
		/// C-types' signedness.
		TypeSignedness typeSignedness;
		/// Bitwidth used for types not in @c typeWidths.
		unsigned defaultBitWidth = 0;
};

} // namespace ctypesparser
} // namespace retdec

#endif
