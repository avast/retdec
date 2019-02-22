#ifndef RETDEC_BORLAND_AST_TYPES_H
#define RETDEC_BORLAND_AST_TYPES_H

#include <memory>
#include <string>
#include <vector>

#include "llvm/Demangle/StringView.h"
#include "llvm/Demangle/borland_ast.h"

namespace retdec {
namespace demangler {
namespace borland {

class Context;

enum class ThreeStateSignness
{
	signed_char,
	unsigned_char,
	no_prefix
};

// TODO isVolatile, isConst and isRestricted change to class with 3 bools

class TypeNode : public Node
{
public:
	Qualifiers quals();
	StringView typeName() const;

	void printLeft(std::ostream &s) const override;

protected:
	TypeNode(const StringView &typeName, const Qualifiers &quals);

protected:
	StringView _typeName;
	Qualifiers _quals;
};

/**
 * @brief Node for representation of built-in types.
 */
class BuiltInTypeNode : public TypeNode
{
public:
	static std::shared_ptr<BuiltInTypeNode> create(
		Context &context,
		const StringView &typeName,
		const Qualifiers &quals);

protected:
	BuiltInTypeNode(const StringView &typeName, const Qualifiers &quals);
};

class CharTypeNode : public BuiltInTypeNode
{
public:
	static std::shared_ptr<CharTypeNode> create(
		Context &context,
		ThreeStateSignness signness,
		const Qualifiers &quals);

	ThreeStateSignness signness();

	void printLeft(std::ostream &s) const override;

private:
	CharTypeNode(ThreeStateSignness signness, const Qualifiers &quals);

private:
	ThreeStateSignness _signness;
};

class IntegralTypeNode : public BuiltInTypeNode
{
public:
	static std::shared_ptr<IntegralTypeNode> create(
		Context &context,
		const StringView &typeName,
		bool isUnsigned,
		const Qualifiers &quals);

	bool isUnsigned();

	void printLeft(std::ostream &s) const override;

private:
	IntegralTypeNode(const StringView &typeName, bool isUnsigned, const Qualifiers &quals);

private:
	bool _isUnsigned;
};

class FloatTypeNode : public BuiltInTypeNode
{
public:
	static std::shared_ptr<FloatTypeNode> create(
		Context &context,
		const StringView &typeName,
		const Qualifiers &quals);

private:
	FloatTypeNode(const StringView &typeName, const Qualifiers &quals);
};

class NamedTypeNode : public TypeNode
{
public:
	static std::shared_ptr<NamedTypeNode> create(
		Context &context,
		std::shared_ptr<Node> typeName,
		const Qualifiers &quals);

	std::shared_ptr<Node> name();

	void printLeft(std::ostream &s) const override;

private:
	NamedTypeNode(std::shared_ptr<Node> typeName, const Qualifiers &quals);

private:
	std::shared_ptr<Node> _typeName;
};

class PointerTypeNode : public TypeNode
{
public:
	static std::shared_ptr<PointerTypeNode> create(
		Context context,
		std::shared_ptr<Node> pointee,
		const Qualifiers &quals);

	std::shared_ptr<Node> pointee();

	void printLeft(std::ostream &s) const override;

	void printRight(std::ostream &s) const override;

private:
	PointerTypeNode(std::shared_ptr<Node> pointee, const Qualifiers &quals);

private:
	std::shared_ptr<Node> _pointee;
};

class ReferenceTypeNode : public TypeNode
{
public:
	static std::shared_ptr<ReferenceTypeNode> create(
		Context &context,
		std::shared_ptr<Node> pointee);

	std::shared_ptr<Node> pointee();

	void printLeft(std::ostream &s) const override;

	void printRight(std::ostream &s) const override;

private:
	explicit ReferenceTypeNode(std::shared_ptr<Node> pointee);

private:
	std::shared_ptr<Node> _pointee;
};

class RReferenceTypeNode : public TypeNode
{
public:
	static std::shared_ptr<RReferenceTypeNode> create(
		Context &context,
		std::shared_ptr<Node> pointee);

	std::shared_ptr<Node> pointee();

	void printLeft(std::ostream &s) const override;

	void printRight(std::ostream &s) const override;

private:
	explicit RReferenceTypeNode(std::shared_ptr<Node> pointee);

private:
	std::shared_ptr<Node> _pointee;
};

class ArrayNode : public TypeNode
{
public:
	static std::shared_ptr<ArrayNode> create(
		Context &context,
		std::shared_ptr<retdec::demangler::borland::Node> pointee,
		unsigned size,
		const Qualifiers &quals);

	void printLeft(std::ostream &s) const override;

	void printRight(std::ostream &s) const override;

private:
	ArrayNode(std::shared_ptr<retdec::demangler::borland::Node> pointee, unsigned size, const Qualifiers &quals);

private:
	std::shared_ptr<Node> _pointee;
	unsigned _size;
};

class FunctionTypeNode: public TypeNode
{
public:
	static std::shared_ptr<FunctionTypeNode> create(
		Context &context,
		CallConv callConv,
		std::shared_ptr<Node> params,
		std::shared_ptr<Node> retType,
		Qualifiers &quals);

	void printLeft(std::ostream &s) const override;

	void printRight(std::ostream &s) const override;

private:
	FunctionTypeNode(
		CallConv callConv,
		std::shared_ptr<Node> params,
		std::shared_ptr<Node> retType,
		Qualifiers &quals);

private:
	CallConv _callConv;
	std::shared_ptr<Node> _params;
	std::shared_ptr<Node> _retType;
};

}    // borland
}    // demangler
}    // retdec

#endif //RETDEC_BORLAND_AST_TYPES_H
