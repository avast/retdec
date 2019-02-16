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

/**
 * @brief Base class for all nodes in AST.
 */
class Node
{
public:
	enum class Kind
	{
		KFunction,
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
	};

public:
	explicit Node(Kind kind, bool has_right_side = false);

	virtual ~Node() = default;

	void print(std::ostream &s) const;

	std::string str() const;

	Kind kind() const;

protected:
	virtual void printLeft(std::ostream &s) const = 0;

	virtual void printRight(std::ostream &s) const;

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
	enum class CallConv
	{
		fastcall,
		cdecl,
		pascal,
		stdcall,
		unknown,
	};

public:
	static std::shared_ptr<FunctionNode> create(
		std::shared_ptr<Node> name,
		CallConv call_conv,
		std::shared_ptr<Node> params,
		std::shared_ptr<Node> retType,
		bool isVolatile,
		bool isConst
	);

private:
	FunctionNode(
		std::shared_ptr<Node> name,
		CallConv call_conv,
		std::shared_ptr<Node> params,
		std::shared_ptr<Node> retType,
		bool isVolatile,
		bool isConst);

	void printLeft(std::ostream &s) const override;

private:
	CallConv _call_conv;
	std::shared_ptr<Node> _name;
	std::shared_ptr<Node> _params;
	std::shared_ptr<Node> _retType;
	bool _isVolatile;
	bool _isConst;

};

class TemplateNode : public Node
{
public:
	static std::shared_ptr<TemplateNode> create(std::shared_ptr<Node> name, std::shared_ptr<Node> params);

private:
	TemplateNode(std::shared_ptr<Node> name, std::shared_ptr<Node> params);

	void printLeft(std::ostream &s) const override;

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
	static std::shared_ptr<NameNode> create(const StringView &name);

private:
	explicit NameNode(const StringView &name);

	void printLeft(std::ostream &s) const override;

private:
	StringView _name;
};

/**
 * @brief Node for representation of nested names.
 */
class NestedNameNode : public Node
{
public:
	static std::shared_ptr<NestedNameNode> create(
		std::shared_ptr<Node> super, std::shared_ptr<Node> name);

private:
	NestedNameNode(std::shared_ptr<Node> super, std::shared_ptr<Node> name);

	void printLeft(std::ostream &s) const override;

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

private:
	NodeArray();

	void printLeft(std::ostream &s) const override;

private:
	std::vector<std::shared_ptr<Node>> _nodes;
};

}    // borland
}    // demangler
}    // retdec

#endif //RETDEC_BORLAND_AST_H
