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

#include "retdec/ctypes/array_type.h"
#include "retdec/ctypes/call_convention.h"
#include "retdec/ctypes/composite_type.h"
#include "retdec/ctypes/enum_type.h"
#include "retdec/ctypes/function.h"
#include "retdec/ctypes/function_type.h"
#include "retdec/ctypes/integral_type.h"
#include "retdec/ctypes/parameter.h"
#include "retdec/ctypesparser/exceptions.h"

namespace retdec {
namespace ctypes {

class Context;
class FloatingPointType;
class Module;
class PointerType;
class StructType;
class Type;
class UnionType;

} // namespace ctypes

namespace ctypesparser {

/**
* @brief A base class for parsing C-types.
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
		/// Call convention used when JSON does not contain one.
		retdec::ctypes::CallConvention defaultCallConv;
};

} // namespace ctypesparser
} // namespace retdec

#endif
