/**
 * @file include/llvm/Demangle/borland_ast.h
 * @brief Representation of syntactic tree for borland demangler.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BORLAND_AST_H
#define RETDEC_BORLAND_AST_H

#include <memory>
#include <string>
#include <vector>

#include "llvm/Demangle/StringView.h"

namespace retdec {
namespace demangler {
namespace borland {

class Context;
class FunctionTypeNode;

using StringView = llvm::itanium_demangle::StringView;

class Qualifiers
{
public:
	Qualifiers(bool isVolatile, bool isConst);

	bool isVolatile() const;

	bool isConst() const;

	void printSpaceL(std::ostream &s) const;

	void printSpaceR(std::ostream &s) const;

private:
	bool _isVolatile;
	bool _isConst;
};

enum class CallConv
{
	fastcall,
	cdecl,
	pascal,
	stdcall,
	unknown,
};

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
		KTypeNode,
		KBuiltInType,
		KPointerType,
		KIntegralType,
		KCharType,
		KFloatType,
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

/**
 * Node for representation of functions.
 */
class FunctionNode : public Node
{
public:
	static std::shared_ptr<FunctionNode> create(
		std::shared_ptr<Node> name,
		std::shared_ptr<FunctionTypeNode> funcType);

	void printLeft(std::ostream &s) const override;

private:
	FunctionNode(
		std::shared_ptr<Node> name,
		std::shared_ptr<FunctionTypeNode> funcType);

private:
	std::shared_ptr<Node> _name;
	std::shared_ptr<FunctionTypeNode> _funcNode;
};

class TemplateNode : public Node
{
public:
	static std::shared_ptr<TemplateNode> create(std::shared_ptr<Node> name, std::shared_ptr<Node> params);

	void printLeft(std::ostream &s) const override;

private:
	TemplateNode(std::shared_ptr<Node> name, std::shared_ptr<Node> params);

private:
	std::shared_ptr<Node> _name;
	std::shared_ptr<Node> _params;
};

/**
 * @brief Node for representation of names.
 */
class NameNode : public Node
{
public:
	static std::shared_ptr<NameNode> create(Context &context, const StringView &name);

	void printLeft(std::ostream &s) const override;

private:
	explicit NameNode(const StringView &name);

private:
	StringView _name;		// TODO prerob na string
};

/**
 * @brief Node for representation of nested names.
 */
class NestedNameNode : public Node
{
public:
	static std::shared_ptr<NestedNameNode> create(
		Context &context, std::shared_ptr<Node> super, std::shared_ptr<Node> name);

	void printLeft(std::ostream &s) const override;

	std::shared_ptr<Node> super();

	std::shared_ptr<Node> name();

private:
	NestedNameNode(std::shared_ptr<Node> super, std::shared_ptr<Node> name);

private:
	std::shared_ptr<Node> _super;
	std::shared_ptr<Node> _name;
};

/**
 * @brief Node for representation of arrays of nodes.
 */
class NodeArray : public Node
{
public:
	static std::shared_ptr<NodeArray> create();

	void addNode(std::shared_ptr<Node> node);

	bool empty() const;

	size_t size();

	void printLeft(std::ostream &s) const override;

	std::shared_ptr<Node> get(unsigned i) const;

private:
	NodeArray();

private:
	std::vector<std::shared_ptr<Node>> _nodes;
};

class ConversionOperatorNode : public Node
{
public:
	static std::shared_ptr<ConversionOperatorNode> create(Context &context, std::shared_ptr<Node> type);

	void printLeft(std::ostream &s) const override;

private:
	ConversionOperatorNode(std::shared_ptr<Node> type);

private:
	std::shared_ptr<Node> _type;
};

}    // borland
}    // demangler
}    // retdec

#endif //RETDEC_BORLAND_AST_H
