/**
* @file src/demangler/borland_ast/function_type.cpp
* @brief Representation of function_types.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#include <sstream>

#include "retdec/demangler/borland_ast/function_type.h"

namespace retdec {
namespace demangler {
namespace borland {

/**
 * @brief Private constructor for function types. Use create().
 */
FunctionTypeNode::FunctionTypeNode(
	CallConv callConv,
	std::shared_ptr<NodeArray> params,
	std::shared_ptr<TypeNode> retType,
	Qualifiers &quals,
	bool isVarArg) :
	TypeNode(quals), _callConv(callConv), _params(std::move(params)), _retType(std::move(retType)), _isVarArg(isVarArg)
{
	_kind = Kind::KFunctionType;
	_has_right = true;
}

/**
 * @brief Function for creating function types.
 * @param callConv Calling convention.
 * @param params Node representing parameters.
 * @param retType Return type, can be nullptr.
 * @param quals Function qualifiers.
 * @param isVarArg wheater function is varidic.
 * @return Node representing function type.
 */
std::shared_ptr<FunctionTypeNode> FunctionTypeNode::create(
	CallConv callConv,
	std::shared_ptr<NodeArray> params,
	std::shared_ptr<TypeNode> retType,
	Qualifiers &quals,
	bool isVarArg)
{
	return std::shared_ptr<FunctionTypeNode>(new FunctionTypeNode(callConv, params, retType, quals, isVarArg));
}

CallConv FunctionTypeNode::callConv()
{
	return _callConv;
}

std::shared_ptr<NodeArray> FunctionTypeNode::params()
{
	return _params;
}

std::shared_ptr<TypeNode> FunctionTypeNode::retType()
{
	return _retType;
}

bool FunctionTypeNode::isVarArg()
{
	return _isVarArg;
}

/**
 * Prints left side of function type to output stream.
 */
void FunctionTypeNode::printLeft(std::ostream &s) const
{
	if (_retType) {
		if (_retType->hasRight()) {
			_retType->printLeft(s);
		} else {
			_retType->print(s);
			s << " ";
		}
	}

	switch (_callConv) {
	case CallConv::cc_fastcall:
		s << "__fastcall ";
		break;
	case CallConv::cc_stdcall:
		s << "__stdcall ";
		break;
	default:
		break;
	}
}

/**
 * Prints right side of function type to output stream.
 */
void FunctionTypeNode::printRight(std::ostream &s) const
{
	s << "(";
	if (_params) {
		_params->print(s);
	}
	if (_isVarArg) {
		s << ", ...";
	}
	s << ")";

	if (_retType && _retType->hasRight()) {
		_retType->printRight(s);
	}

	_quals.printSpaceL(s);
}

}    // borland
}    // demangler
}    // retdec
