/**
 * @file include/retdec/demangler/context.h
 * @brief Storage for all created nodes in borland AST.
 * @copyright (c) 2018 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CONTEXT_H
#define RETDEC_CONTEXT_H

#include <memory>
#include <map>

namespace retdec {
namespace demangler {
namespace borland {

class Node;
class TypeNode;
class BuiltInTypeNode;
class IntegralTypeNode;
class FloatTypeNode;
class CharTypeNode;
enum class ThreeStateSignedness;
class PointerTypeNode;
class ReferenceTypeNode;
class RReferenceTypeNode;
class NamedTypeNode;
class Qualifiers;
class NameNode;
class NestedNameNode;
class ArrayNode;

/**
 * @brief Storage for functions, types and names.
 * Used for cacheing.
 */
class Context
{
public:
	Context() = default;

	/// @name Built-in types.
	/// @{
	std::shared_ptr<BuiltInTypeNode> getBuiltInType(
		const std::string &name,
		const Qualifiers &quals
	) const;

	void addBuiltInType(
		const std::shared_ptr<BuiltInTypeNode> &type
	);
	/// @}

	/// @name Char type.
	/// @{
	std::shared_ptr<CharTypeNode> getCharType(
		const ThreeStateSignedness &signedness,
		const Qualifiers &quals
	) const;

	void addCharType(
		const std::shared_ptr<CharTypeNode> &type
	);
	/// @}

	/// @name Integral type.
	/// @{
	std::shared_ptr<IntegralTypeNode> getIntegralType(
		const std::string &name,
		bool isUnsigned,
		const Qualifiers &quals
	) const;

	void addIntegralType(
		const std::shared_ptr<IntegralTypeNode> &type
	);
	/// @}

	/// @name Floating point number types.
	/// @{
	std::shared_ptr<FloatTypeNode> getFloatType(
		const std::string &name,
		const Qualifiers &quals
	) const;

	void addFloatType(
		const std::shared_ptr<FloatTypeNode> &type
	);
	/// @}

	/// @name Pointer types.
	/// @{
	std::shared_ptr<PointerTypeNode> getPointerType(
		std::shared_ptr<Node> pointee,
		const Qualifiers &quals
	) const;

	void addPointerType(
		const std::shared_ptr<PointerTypeNode> &type
	);
	/// @}

	/// @name Reference types.
	/// @{
	std::shared_ptr<ReferenceTypeNode> getReferenceType(
		std::shared_ptr<Node> pointee
	) const;

	void addReferenceType(
		const std::shared_ptr<ReferenceTypeNode> &type
	);
	/// @}

	/// @name R-value reference types.
	/// @{
	std::shared_ptr<RReferenceTypeNode> getRReferenceType(
		std::shared_ptr<Node> pointee
	) const;

	void addRReferenceType(
		const std::shared_ptr<RReferenceTypeNode> &type
	);
	/// @}

	/// @name Named types.
	/// @{
	std::shared_ptr<NamedTypeNode> getNamedType(
		const std::string &name,
		const Qualifiers &quals
	) const;

	void addNamedType(
		const std::string &mangled,
		const Qualifiers &quals,
		const std::shared_ptr<NamedTypeNode> &type
	);
	/// @}

	std::shared_ptr<Node> getFunction(const std::string &mangled) const;    // TODO remove and move to bin2llvm::demangler
	void addFunction(
		const std::string &mangled,
		const std::shared_ptr<Node> &function);

	/// @name Names.
	/// @{
	std::shared_ptr<NameNode> getName(
		const std::string &name
	) const;

	void addName(
		const std::shared_ptr<NameNode> &name
	);
	/// @}

	/// @name Nested names.
	/// @{
	std::shared_ptr<NestedNameNode> getNestedName(
		std::shared_ptr<Node> super,
		std::shared_ptr<Node> name
	);

	void addNestedName(
		const std::shared_ptr<NestedNameNode> &name
	);
	/// @}

	/// @name Array types.
	/// @{
	std::shared_ptr<ArrayNode> getArray(
		std::shared_ptr<Node> pointee,
		unsigned size,
		const Qualifiers &quals
	);

	void addArrayType(
		const std::shared_ptr<ArrayNode> &array
	);
	/// @}

private:
	using BuiltInTypeNodes = std::map<
		std::tuple<std::string, bool, bool>,
		std::shared_ptr<BuiltInTypeNode>
	>;
	BuiltInTypeNodes builtInTypes;

	using CharTypeNodes = std::map<
		std::tuple<ThreeStateSignedness, bool, bool>,
		std::shared_ptr<CharTypeNode>
	>;
	CharTypeNodes charTypes;

	using IntegralTypeNodes = std::map<
		std::tuple<std::string, bool, bool, bool>,
		std::shared_ptr<IntegralTypeNode>
	>;
	IntegralTypeNodes integralTypes;

	using PointerTypeNodes = std::map<
		std::tuple<std::shared_ptr<Node>, bool, bool>,
		std::shared_ptr<PointerTypeNode>
	>;
	PointerTypeNodes pointerTypes;

	using ReferenceTypeNodes = std::map<
		std::shared_ptr<Node>,
		std::shared_ptr<ReferenceTypeNode>
	>;
	ReferenceTypeNodes referenceTypes;

	using RReferenceTypeNodes = std::map<
		std::shared_ptr<Node>,
		std::shared_ptr<RReferenceTypeNode>
	>;
	RReferenceTypeNodes rReferenceTypes;

	using NamedTypeNodes = std::map<
		std::tuple<std::string, bool, bool>,
		std::shared_ptr<NamedTypeNode>
	>;
	NamedTypeNodes namedTypes;

	using FunctionNodes = std::map<
		std::string,
		std::shared_ptr<Node>
	>;
	FunctionNodes functions;

	using NameNodes = std::map<
		std::string,
		std::shared_ptr<NameNode>
	>;
	NameNodes nameNodes;

	using NestedNameNodes =std::map<
		std::tuple<std::shared_ptr<Node>, std::shared_ptr<Node>>,
		std::shared_ptr<NestedNameNode>
	>;
	NestedNameNodes nestedNameNodes;

	using ArrayNodes = std::map<
		std::tuple<std::shared_ptr<Node>, unsigned, bool, bool>,
		std::shared_ptr<ArrayNode>
	>;
	ArrayNodes arrayNodes;

};

}    // borland
}    // demangler
}    // retdec

#endif //RETDEC_CONTEXT_H
