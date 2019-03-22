#include "retdec/utils/container.h"
#include "retdec/ctypesparser/ast_ctypes_parser.h"

namespace retdec {
namespace ctypesparser {

ctypes::IntegralType::Signess AstToCtypesParser::toSigness(bool isUnsigned)
{
	return isUnsigned ? ctypes::IntegralType::Signess::Unsigned : ctypes::IntegralType::Signess::Signed;
}

ctypes::IntegralType::Signess AstToCtypesParser::toSigness(const std::string &typeName)
{
	if (typeName.substr(0, 9) == "unsigned ") {
		return ctypes::IntegralType::Signess::Unsigned;
	}

	/* find in map, if nothing found, then probably signed */
	return utils::mapGetValueOrDefault(typeSignedness, typeName, ctypes::IntegralType::Signess::Signed);
}

ctypes::FunctionType::VarArgness AstToCtypesParser::toVarArgness(bool isVarArg)
{
	using VarArgness = ctypes::Function::VarArgness;

	return isVarArg ? VarArgness::IsVarArg : VarArgness::IsNotVarArg;
}

}
}