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
		KBuiltInType,
		KFunction,
		KName,
		KNestedName,
		KNodeArray,
		KPointerType,
		KIntegralType,
		KCharType,
		KFloatType,
	};

public:
	explicit Node(Kind kind, bool has_right_side = false);

	virtual ~Node() = default;

	void print(std::ostream &s);

	std::string str();

	Kind kind();

protected:
	virtual void printLeft(std::ostream &s) = 0;

	virtual void printRight(std::ostream &s);

protected:
	Kind _kind;
	bool _has_right;
};

class TypeFactory {
public:
	static std::unique_ptr<Node> createBool();
	static std::unique_ptr<Node> createWChar();
	static std::unique_ptr<Node> createVoid();
	static std::unique_ptr<Node> createSignedChar();	// signed char, char and unsigned char are by definition separate
	static std::unique_ptr<Node> createChar(bool isUnsigned = false);
	static std::unique_ptr<Node> createShort(bool isUnsigned = false);
	static std::unique_ptr<Node> createInt(bool isUnsigned = false);
	static std::unique_ptr<Node> createLong(bool isUnsigned = false);
	static std::unique_ptr<Node> createLongLong(bool isUnsigned = false);
	static std::unique_ptr<Node> createFloat();
	static std::unique_ptr<Node> createDouble();
	static std::unique_ptr<Node> createLongDouble();
//	static std::unique_ptr<Node> createNamedType(const StringView &typeName);
};

/**
 * @brief Node for representation of built-in types.
 */
class BuiltInType : public Node
{
public:
	static std::unique_ptr<BuiltInType> create(const StringView &typeName);

protected:
	explicit BuiltInType(const StringView &typeName);

	void printLeft(std::ostream &s) override;

protected:
	StringView _typeName;
};

class CharType : public BuiltInType
{
public:
	enum class Signness {
		signed_char,
		unsigned_char,
		not_stated
	};

public:
	static std::unique_ptr<CharType> create(Signness signness);

private:
	explicit CharType(Signness signness);

	void printLeft(std::ostream &s) override;

private:
	Signness _signness;
};

class IntegralType : public BuiltInType
{
public:
	static std::unique_ptr<IntegralType> create(const StringView &typeName, bool isUnsigned = false);

private:
	IntegralType(const StringView &typeName, bool isUnsigned);

	void printLeft(std::ostream &s) override;

private:
	bool _isUnsigned;
};

class FloatType : public BuiltInType
{
public:
	static std::unique_ptr<FloatType> create(const StringView &typeName);

private:
	explicit FloatType(const StringView &typeName);
};

class PointerType : public Node
{
public:
	static std::unique_ptr<PointerType> create(std::unique_ptr<Node> pointee);

private:
	explicit PointerType(std::unique_ptr<Node> pointee);

	void printLeft(std::ostream &s) override;

protected:
	std::unique_ptr<Node> _pointee;
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
	static std::unique_ptr<FunctionNode> create(
		std::unique_ptr<Node> name,
		CallConv call_conv = CallConv::unknown,
		std::unique_ptr<Node> params = nullptr
	);

private:
	explicit FunctionNode(
		std::unique_ptr<Node> name,
		CallConv call_conv = CallConv::unknown,
		std::unique_ptr<Node> params = nullptr);

	void printLeft(std::ostream &s) override;

private:
	CallConv _call_conv;
	std::unique_ptr<Node> _name;
	std::unique_ptr<Node> _params;

};

/**
 * @brief Node for representation of names.
 */
class NameNode : public Node
{
public:
	static std::unique_ptr<NameNode> create(const StringView &name);

private:
	explicit NameNode(const StringView &name);

	void printLeft(std::ostream &s) override;

private:
	StringView _name;
};

/**
 * @brief Node for representation of nested names.
 */
class NestedNameNode : public Node
{
public:
	static std::unique_ptr<NestedNameNode> create(
		std::unique_ptr<Node> super, std::unique_ptr<Node> name);

private:
	NestedNameNode(std::unique_ptr<Node> super, std::unique_ptr<Node> name);

	void printLeft(std::ostream &s) override;

private:
	std::unique_ptr<Node> _super;
	std::unique_ptr<Node> _name;
};

/**
 * @brief Node for representation of arrays of nodes.
 */
class NodeArray : public Node
{
public:
	static std::unique_ptr<NodeArray> create();

	void addNode(std::unique_ptr<Node> node);

	bool empty();

private:
	NodeArray();

	void printLeft(std::ostream &s) override;

private:
	std::vector<std::unique_ptr<Node>> _nodes;
};

}    // borland
}    // demangler
}    // retdec

#endif //RETDEC_BORLAND_AST_H
