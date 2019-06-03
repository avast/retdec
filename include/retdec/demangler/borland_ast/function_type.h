/**
* @file include/retdec/demangler/borland_ast/function_type.h
* @brief Representation of function types in borland AST.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_FUNCTION_TYPE_H
#define RETDEC_FUNCTION_TYPE_H

#include "retdec/demangler/borland_ast/type_node.h"
#include "retdec/demangler/borland_ast/node_array.h"
#include "retdec/demangler/borland_ast/type_node.h"

namespace retdec {
namespace demangler {
namespace borland {

enum class CallConv
{
	cc_fastcall,
	cc_cdecl,
	cc_pascal,
	cc_stdcall,
	cc_unknown,
};

/**
 * @brief Representation of function types.
 * Used for information about functions without name.
 */
class FunctionTypeNode : public TypeNode
{
public:
	static std::shared_ptr<FunctionTypeNode> create(
		CallConv callConv,
		std::shared_ptr<NodeArray> params,
		std::shared_ptr<TypeNode> retType,
		Qualifiers &quals,
		bool isVarArg);

	CallConv callConv();

	std::shared_ptr<NodeArray> params();

	std::shared_ptr<TypeNode> retType();

	bool isVarArg();

	void printLeft(std::ostream &s) const override;

	void printRight(std::ostream &s) const override;

private:
	FunctionTypeNode(
		CallConv callConv,
		std::shared_ptr<NodeArray> params,
		std::shared_ptr<TypeNode> retType,
		Qualifiers &quals,
		bool isVarArg);

private:
	CallConv _callConv;
	std::shared_ptr<NodeArray> _params;
	std::shared_ptr<TypeNode> _retType;
	bool _isVarArg;
};

}    // borland
}    // demangler
}    // retdec

#endif //RETDEC_FUNCTION_TYPE_H
