/**
* @file src/demangler/ast_ctypes_parser.cpp
* @brief Base class for all C-types parsers from demangler ASTs.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include "retdec/utils/container.h"
#include "retdec/demangler/ast_ctypes_parser.h"

namespace retdec {
namespace demangler {

/*
 * @brief Finds bit width of type, based on name.
 * Function first looks in typeWidhs map.
 */
unsigned AstToCtypesParser::getBitWidth(const std::string &typeName) const
{
	if (utils::mapHasKey(typeWidths, typeName)) {
		return utils::mapGetValueOrDefault(typeWidths, typeName);
	}

	TypeWidths knownWidths {
		{"int16_t", 16},
		{"uint16_t", 16},
		{"int32_t", 32},
		{"uint32_t", 32},
		{"int64_t", 64},
		{"uint64_t", 64},
		{"int128_t", 128},
		{"uint128_t", 128},
		{"__int64", 64},
		{"unsigned __int64", 64},
		{"__int128", 128},
		{"unsigned __int128", 128},
		{"char16_t", 16},
		{"char32_t", 32},
		{"__float128", 128},
		{"decimal16", 16},
		{"decimal32", 32},
		{"decimal64", 64},
		{"decimal128", 128},
		{"void", 0},
	};

	return utils::mapGetValueOrDefault(knownWidths, typeName, defaultBitWidth);
}

/*
 * @ brief Converts bool value to IntegralType::Signess
 */
ctypes::IntegralType::Signess AstToCtypesParser::toSigness(bool isUnsigned) const
{
	return isUnsigned ? ctypes::IntegralType::Signess::Unsigned : ctypes::IntegralType::Signess::Signed;
}

/*
 * @brief Based on type name returns IntegralType::Signess
 * Info in type signedness map is more important.
 */
ctypes::IntegralType::Signess AstToCtypesParser::toSigness(const std::string &typeName) const
{
	if (utils::mapHasKey(typeSignedness, typeName)) {
		return utils::mapGetValueOrDefault(typeSignedness, typeName);
	}

	if (typeName.substr(0, 9) == "unsigned "
		|| typeName.substr(0, 4) == "uint"
		|| typeName == "char16_t"
		|| typeName == "char32_t") {
		return ctypes::IntegralType::Signess::Unsigned;
	}

	/* if nothing found, then probably signed */
	return ctypes::IntegralType::Signess::Signed;
}

/*
 * @brief Converts bool value to Function::VarArgness
 */
ctypes::FunctionType::VarArgness AstToCtypesParser::toVarArgness(bool isVarArg) const
{
	using VarArgness = ctypes::Function::VarArgness;

	return isVarArg ? VarArgness::IsVarArg : VarArgness::IsNotVarArg;
}

}
}