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
#include "retdec/ctypes/parameter.h"
#include "retdec/ctypesparser/exceptions.h"

namespace retdec {
namespace ctypes {

class Context;
class IntegralType;
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
* Parsers for C-types in some specific format should override @c parse(...)
* functions.
*/
class CTypesParser
{
	public:
		/// Set container for C-types' bit width.
		using TypeWidths = std::map<std::string, unsigned>;

	public:
		virtual ~CTypesParser() = default;

		virtual std::unique_ptr<retdec::ctypes::Module> parse(
			std::istream &stream,
			const TypeWidths &typeWidths = {},
			const retdec::ctypes::CallConvention &callConvention = retdec::ctypes::CallConvention()) = 0;
		virtual void parseInto(std::istream &stream,
			std::unique_ptr<retdec::ctypes::Module> &module,
			const TypeWidths &typeWidths = {},
			const retdec::ctypes::CallConvention &callConvention = retdec::ctypes::CallConvention()) = 0;

	protected:
		CTypesParser();
		CTypesParser(unsigned defaultBitWidth);

	protected:
		/// Container for already parsed functions, types.
		std::shared_ptr<retdec::ctypes::Context> context;
		/// C-types' bit widths.
		TypeWidths typeWidths;
		/// Bitwidth used for types not in @c typeWidths.
		unsigned defaultBitWidth = 0;
		/// Call convention used when JSON does not contain one.
		retdec::ctypes::CallConvention defaultCallConv;
};

} // namespace ctypesparser
} // namespace retdec

#endif
