/**
* @file include/retdec/demangler/borland_ast/node.h
* @brief Base class for all nodes in borland AST.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_NODE_H
#define RETDEC_NODE_H

#include <memory>
#include <string>
#include <vector>

namespace retdec {
namespace demangler {
namespace borland {

/**
 * @brief Base class for all nodes in AST.
 */
class Node
{
public:
	enum class Kind
	{
		KFunction,
		KFunctionType,
		KName,
		KNestedName,
		KNodeArray,
		KNodeString,
		KTypeNode,
		KBuiltInType,
		KPointerType,
		KIntegralType,
		KCharType,
		KFloatType,
		KParentheses,
		KReferenceType,
		KRReferenceType,
		KNamedType,
		KTemplateNode,
		KArrayNode,
		KConversionOperator,
	};

public:
	explicit Node(Kind kind, bool has_right_side = false);

	virtual ~Node() = default;

	void print(std::ostream &s) const;

	std::string str() const;

	Kind kind() const;

	virtual void printLeft(std::ostream &s) const = 0;

	virtual void printRight(std::ostream &s) const;

	bool hasRight();

protected:
	Kind _kind;
	bool _has_right;
};

}
}
}

#endif //RETDEC_NODE_H
