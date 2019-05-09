#include "retdec/utils/container.h"
#include "retdec/ctypesparser/ast_ctypes_parser.h"

namespace retdec {
namespace ctypesparser {

/*
 * @brief Finds bit width of type, based on name.
 * Function first looks in typeWidhs map.
 */
unsigned AstToCtypesParser::toBitWidth(const std::string &typeName) const	// TODO regexp for int sizes
{
	if (utils::mapHasKey(typeWidths, typeName)) {
		return utils::mapGetValueOrDefault(typeWidths, typeName);
	}

	if (typeName.substr(0, 4) == "uint"
		|| typeName.substr(0, 3) == "int")
	{
		if (typeName == "int8_t" || typeName == "uint8_t")
		{
			return 8;
		}
		else if (typeName == "int16_t" || typeName == "int32_t")
		{
			return 16;
		}
		else if (typeName == "int32_t" || typeName == "uint32_t")
		{
			return 32;
		}
		else if (typeName == "int64_t" || typeName == "uint64_t")
		{
			return 64;
		}
		else if (typeName == "int128_t" || typeName == "uint128_t")
		{
			return 128;
		}
	}

	if (typeName == "void")
	{
		return 0;
	}

	return defaultBitWidth;
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