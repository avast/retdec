/**
 * @file include/retdec/demangler/borland_ast_types.h
 * @brief Representation of types in demangler ast.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BORLAND_AST_TYPES_H
#define RETDEC_BORLAND_AST_TYPES_H

#include <memory>
#include <string>
#include <vector>

#include "retdec/demangler/borland_ast.h"

namespace retdec {
namespace demangler {
namespace borland {

class Context;

/**
 * @brief Signedness used for chars.
 * Chars can be signed char, unsigned char and char, which are by standard distinct.
 * These types are all mangled differently.
 */
enum class ThreeStateSignedness
{
	signed_char,
	unsigned_char,
	no_prefix
};

/**
 * @brief Base class for all type nodes.
 */
class TypeNode : public Node
{
public:
	Qualifiers quals();

protected:
	explicit TypeNode(const Qualifiers &quals);	// TODO kind ako volitelny parameter

protected:
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
		const std::string &typeName,
		const Qualifiers &quals);

	std::string typeName() const;

	void printLeft(std::ostream &s) const override;

protected:
	BuiltInTypeNode(const std::string &typeName, const Qualifiers &quals);

protected:
	std::string _typeName;
};

/**
 * @brief Representation of char types.
 */
class CharTypeNode : public BuiltInTypeNode
{
public:
	static std::shared_ptr<CharTypeNode> create(
		Context &context,
		ThreeStateSignedness signedness,
		const Qualifiers &quals);

	ThreeStateSignedness signedness();

	void printLeft(std::ostream &s) const override;

private:
	CharTypeNode(ThreeStateSignedness signedness, const Qualifiers &quals);

private:
	ThreeStateSignedness _signedness;
};

/**
 * @brief Representation of integral types.
 */
class IntegralTypeNode : public BuiltInTypeNode
{
public:
	static std::shared_ptr<IntegralTypeNode> create(
		Context &context,
		const std::string &typeName,
		bool isUnsigned,
		const Qualifiers &quals);

	bool isUnsigned();

	void printLeft(std::ostream &s) const override;

private:
	IntegralTypeNode(const std::string &typeName, bool isUnsigned, const Qualifiers &quals);

private:
	bool _isUnsigned;
};

/**
 * @brief Representaion of floating point types.
 */
class FloatTypeNode : public BuiltInTypeNode
{
public:
	static std::shared_ptr<FloatTypeNode> create(
		Context &context,
		const std::string &typeName,
		const Qualifiers &quals);

private:
	FloatTypeNode(const std::string &typeName, const Qualifiers &quals);
};

/**
 * @brief Representation of named types.
 */
class NamedTypeNode : public TypeNode
{
public:
	static std::shared_ptr<NamedTypeNode> create(
		std::shared_ptr<Node> typeName,
		const Qualifiers &quals);

	std::shared_ptr<Node> name();

	void printLeft(std::ostream &s) const override;

private:
	NamedTypeNode(std::shared_ptr<Node> typeName, const Qualifiers &quals);

private:
	std::shared_ptr<Node> _typeName;
};

/**
 * @brief Representation of pointers.
 */
class PointerTypeNode : public TypeNode
{
public:
	static std::shared_ptr<PointerTypeNode> create(
		Context &context,
		const std::shared_ptr<Node> &pointee,
		const Qualifiers &quals);

	std::shared_ptr<Node> pointee();

	void printLeft(std::ostream &s) const override;

	void printRight(std::ostream &s) const override;

private:
	PointerTypeNode(const std::shared_ptr<Node> &pointee, const Qualifiers &quals);

private:
	std::shared_ptr<Node> _pointee;
};

/**
 * @brief Representation of references.
 */
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

/**
 * @brief Representation of R-value references.
 */
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

/**
 * @brief Representation of array types.
 */
class ArrayNode : public TypeNode
{
public:
	static std::shared_ptr<ArrayNode> create(
		Context &context,
		std::shared_ptr<retdec::demangler::borland::Node> pointee,
		unsigned size,
		const Qualifiers &quals);

	std::shared_ptr<Node> pointee();

	unsigned size();

	void printLeft(std::ostream &s) const override;

	void printRight(std::ostream &s) const override;

private:
	ArrayNode(std::shared_ptr<retdec::demangler::borland::Node> pointee, unsigned size, const Qualifiers &quals);

private:
	std::shared_ptr<Node> _pointee;
	unsigned _size;
};

/**
 * @brief Representation of function types.
 * Used for information about functions without name.
 * @example pointer to function as parameter
 */
class FunctionTypeNode: public TypeNode
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

#endif //RETDEC_BORLAND_AST_TYPES_H
