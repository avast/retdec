
#ifndef RETDEC_CONTEXT_H
#define RETDEC_CONTEXT_H

#include <memory>
#include <map>

#include "llvm/Demangle/StringView.h"

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

class Context
{
public:
	Context() = default;

	bool hasBuiltInType(
		const StringView &name, bool isVolatile, bool isConst) const;
	std::shared_ptr<BuiltInTypeNode> getBuiltInType(
		const StringView &name, bool isVolatile, bool isConst) const;
	void addBuiltInType(
		const std::shared_ptr<BuiltInTypeNode> &type);

	bool hasCharType(
		const ThreeStateSignness &signness, bool isVolatile, bool isConst) const;
	std::shared_ptr<CharTypeNode> getCharType(
		const ThreeStateSignness &signness, bool isVolatile, bool isConst) const;
	void addCharType(
		const std::shared_ptr<CharTypeNode> &type);

	bool hasIntegralType(
		const StringView &name, bool isUnsigned, bool isVolatile, bool isConst) const;
	std::shared_ptr<IntegralTypeNode> getIntegralType(
		const StringView &name, bool isUnsigned, bool isVolatile, bool isConst) const;
	void addIntegralType(
		const std::shared_ptr<IntegralTypeNode> &type);

	bool hasFloatType(
		const StringView &name, bool isVolatile, bool isConst) const;
	std::shared_ptr<FloatTypeNode> getFloatType(
		const StringView &name, bool isVolatile, bool isConst) const;
	void addFloatType(
		const std::shared_ptr<FloatTypeNode> &type);

	bool hasPointerType(
		std::shared_ptr<Node> pointee, bool isVolatile, bool isConst) const;
	std::shared_ptr<PointerTypeNode> getPointerType(
		std::shared_ptr<Node> pointee, bool isVolatile, bool isConst) const;
	void addPointerType(
		const std::shared_ptr<PointerTypeNode> &type);

	bool hasReferenceType(std::shared_ptr<Node> pointee) const;
	std::shared_ptr<ReferenceTypeNode> getReferenceType(std::shared_ptr<Node> pointee) const;
	void addReferenceType(const std::shared_ptr<ReferenceTypeNode> &type);

//	bool hasNamedType(
//		const std::string &name, bool isVolatile, bool isConst) const;
//	std::shared_ptr<NamedTypeNode> getNamedType(
//		const std::string &name, bool isVolatile, bool isConst) const;
//	void addNamedType(
//		const std::shared_ptr<NamedTypeNode> &type);

private:
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

//	using NamedTypeNodes = std::map<std::tuple<std::string, bool, bool>, std::shared_ptr<NamedTypeNode>>;;
//	NamedTypeNodes namedTypes;

};

}    // borland
}    // demangler
}    // retdec

#endif //RETDEC_CONTEXT_H
