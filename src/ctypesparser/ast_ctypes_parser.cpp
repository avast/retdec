#include "retdec/utils/container.h"
#include "retdec/ctypesparser/ast_ctypes_parser.h"

namespace retdec {
namespace ctypesparser {

/*
 * @brief Finds bit width of type, based on name.
 * Function first looks in typeWidhs map.
 */
unsigned AstToCtypesParser::toBitWidth(const std::string &typeName) const
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

ctypes::IntegralType::Signess AstToCtypesParser::toSigness(bool isUnsigned) const
{
	return isUnsigned ? ctypes::IntegralType::Signess::Unsigned : ctypes::IntegralType::Signess::Signed;
}

ctypes::IntegralType::Signess AstToCtypesParser::toSigness(const std::string &typeName) const
{
	if (typeName.substr(0, 9) == "unsigned "
		|| typeName.substr(0, 4) == "uint"
		|| typeName == "char16_t"
		|| typeName == "char32_t") {
		return ctypes::IntegralType::Signess::Unsigned;
	}

	/* find in map, if nothing found, then probably signed */
	return utils::mapGetValueOrDefault(typeSignedness, typeName, ctypes::IntegralType::Signess::Signed);
}

ctypes::FunctionType::VarArgness AstToCtypesParser::toVarArgness(bool isVarArg) const
{
	using VarArgness = ctypes::Function::VarArgness;

	return isVarArg ? VarArgness::IsVarArg : VarArgness::IsNotVarArg;
}

}
}