
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
enum class ThreeStateSignness;
class PointerTypeNode;
class ReferenceTypeNode;
class NamedTypeNode;
class Qualifiers;
class NameNode;
class NestedNameNode;

class Context
{
public:
	Context() = default;

	std::shared_ptr<BuiltInTypeNode> getBuiltInType(
		const std::string &name,  const Qualifiers &quals) const;
	void addBuiltInType(
		const std::shared_ptr<BuiltInTypeNode> &type);

	std::shared_ptr<CharTypeNode> getCharType(
		const ThreeStateSignness &signness, const Qualifiers &quals) const;
	void addCharType(
		const std::shared_ptr<CharTypeNode> &type);

	std::shared_ptr<IntegralTypeNode> getIntegralType(
		const std::string &name, bool isUnsigned, const Qualifiers &quals) const;
	void addIntegralType(
		const std::shared_ptr<IntegralTypeNode> &type);

	std::shared_ptr<FloatTypeNode> getFloatType(
		const std::string &name,  const Qualifiers &quals) const;
	void addFloatType(
		const std::shared_ptr<FloatTypeNode> &type);

	std::shared_ptr<PointerTypeNode> getPointerType(
		std::shared_ptr<Node> pointee, const Qualifiers &quals) const;
	void addPointerType(
		const std::shared_ptr<PointerTypeNode> &type);

	std::shared_ptr<ReferenceTypeNode> getReferenceType(std::shared_ptr<Node> pointee) const;
	void addReferenceType(const std::shared_ptr<ReferenceTypeNode> &type);

	std::shared_ptr<NamedTypeNode> getNamedType(
		const std::string &name, const Qualifiers &quals) const;
	void addNamedType(
		const std::string &mangled,
		const Qualifiers &quals,
		const std::shared_ptr<NamedTypeNode> &type);

	std::shared_ptr<Node> getFunction(const std::string &mangled) const;
	void addFunction(const std::string &mangled, const std::shared_ptr<Node> &function);

	std::shared_ptr<NameNode> getName(const std::string &name) const;
	void addName(const std::shared_ptr<NameNode> &name);

	std::shared_ptr<NestedNameNode> getNestedName(std::shared_ptr<Node> super, std::shared_ptr<Node> name);
	void addNestedName(const std::shared_ptr<NestedNameNode> &name);

//private:
	using BuiltInTypeNodes = std::map<std::tuple<std::string, bool, bool>, std::shared_ptr<BuiltInTypeNode>>;
	BuiltInTypeNodes builtInTypes;

	using CharTypeNodes = std::map<std::tuple<ThreeStateSignness, bool, bool>, std::shared_ptr<CharTypeNode>>;
	CharTypeNodes charTypes;

	using IntegralTypeNodes = std::map<std::tuple<std::string, bool, bool, bool>, std::shared_ptr<IntegralTypeNode>>;
	IntegralTypeNodes integralTypes;

	using PointerTypeNodes = std::map<std::tuple<std::shared_ptr<Node>, bool, bool>, std::shared_ptr<PointerTypeNode>>;
	PointerTypeNodes pointerTypes;

	using ReferenceTypeNodes = std::map<std::shared_ptr<Node>, std::shared_ptr<ReferenceTypeNode>>;
	ReferenceTypeNodes referenceTypes;

	using NamedTypeNodes = std::map<std::tuple<std::string, bool, bool>, std::shared_ptr<NamedTypeNode>>;;
	NamedTypeNodes namedTypes;

	using FunctionNodes = std::map<std::string, std::shared_ptr<Node>>;
	FunctionNodes functions;

	using NameNodes = std::map<std::string, std::shared_ptr<NameNode>>;
	NameNodes nameNodes;

	using NestedNameNodes = std::map<std::tuple<std::shared_ptr<Node>, std::shared_ptr<Node>>, std::shared_ptr<NestedNameNode>>;
	NestedNameNodes nestedNameNodes;

};

}    // borland
}    // demangler
}    // retdec

#endif //RETDEC_CONTEXT_H
