#include <retdec/utils/container.h>

#include "llvm/Demangle/context.h"
#include "llvm/Demangle/borland_ast_types.h"

namespace retdec {
namespace demangler {
namespace borland {
//
//bool Context::hasBuiltInType(const StringView &name, bool isVolatile, bool isConst) const
//{
//	std::string name_str = std::string{name.begin(), name.size()};
//	auto key = std::make_tuple(name_str, isVolatile, isConst);
//	return retdec::utils::mapHasKey(builtInTypes, key);
//}
//
//std::shared_ptr<BuiltInTypeNode> Context::getBuiltInType(const StringView &name, bool isVolatile, bool isConst) const
//{
//	std::string name_str = std::string{name.begin(), name.size()};
//	auto key = std::make_tuple(name_str, isVolatile, isConst);
//	return retdec::utils::mapGetValueOrDefault(builtInTypes, key);
//}
//
//void Context::addBuiltInType(const std::shared_ptr<BuiltInTypeNode> &type)
//{
//	assert(type && "violated precondition - type cannot be null");
//
//	auto name = type->typeName();
//	std::string name_str = std::string{name.begin(), name.size()};
//	auto key = std::make_tuple(name_str, type->isVolatile(), type->isConst());
//
//	builtInTypes.emplace(key, type);
//}
//
//bool Context::hasCharType(const ThreeStateSignness &signness, bool isVolatile, bool isConst) const
//{
//	auto key = std::make_tuple(signness, isVolatile, isConst);
//	return retdec::utils::mapHasKey(charTypes, key);
//}
//
//std::shared_ptr<CharTypeNode> Context::getCharType(const ThreeStateSignness &signness,
//												   bool isVolatile,
//												   bool isConst) const
//{
//	auto key = std::make_tuple(signness, isVolatile, isConst);
//	return retdec::utils::mapGetValueOrDefault(charTypes, key);
//}
//
//void Context::addCharType(const std::shared_ptr<CharTypeNode> &type)
//{
//	assert(type && "violated precondition - type cannot be null");
//
//	auto signness = type->signness();
//	auto key = std::make_tuple(signness, type->isVolatile(), type->isConst());
//
//	charTypes.emplace(key, type);
//}
//
//bool Context::hasIntegralType(
//	const StringView &name, bool isUnsigned, bool isVolatile, bool isConst) const
//{
//	std::string name_str = std::string{name.begin(), name.size()};
//	auto key = std::make_tuple(name_str, isUnsigned, isVolatile, isConst);
//	return retdec::utils::mapHasKey(integralTypes, key);
//}
//
//std::shared_ptr<IntegralTypeNode> Context::getIntegralType(
//	const StringView &name, bool isUnsigned, bool isVolatile, bool isConst) const
//{
//	std::string name_str = std::string{name.begin(), name.size()};
//	auto key = std::make_tuple(name_str, isUnsigned, isVolatile, isConst);
//	return retdec::utils::mapGetValueOrDefault(integralTypes, key);
//}
//
//void Context::addIntegralType(const std::shared_ptr<IntegralTypeNode> &type)
//{
//	assert(type && "violated precondition - type cannot be null");
//
//	auto name = type->typeName();
//	std::string name_str = std::string{name.begin(), name.size()};
//	auto key = std::make_tuple(
//		name_str, type->isUnsigned(), type->isVolatile(), type->isConst());
//
//	integralTypes.emplace(key, type);
//}
//
//bool Context::hasFloatType(const StringView &name, bool isVolatile, bool isConst) const
//{
//	std::string name_str = std::string{name.begin(), name.size()};
//	auto key = std::make_tuple(name_str, isVolatile, isConst);
//	return retdec::utils::mapHasKey(builtInTypes, key);
//}
//
//std::shared_ptr<FloatTypeNode> Context::getFloatType(const StringView &name, bool isVolatile, bool isConst) const
//{
//	std::string name_str = std::string{name.begin(), name.size()};
//	auto key = std::make_tuple(name_str, isVolatile, isConst);
//	return std::static_pointer_cast<FloatTypeNode>(retdec::utils::mapGetValueOrDefault(builtInTypes, key));
//}
//
//void Context::addFloatType(const std::shared_ptr<FloatTypeNode> &type)
//{
//	assert(type && "violated precondition - type cannot be null");
//
//	auto name = type->typeName();
//	std::string name_str = std::string{name.begin(), name.size()};
//	auto key = std::make_tuple(name_str, type->isVolatile(), type->isConst());
//
//	builtInTypes.emplace(key, type);
//}
//
//bool Context::hasPointerType(
//	std::shared_ptr<retdec::demangler::borland::Node> pointee, bool isVolatile, bool isConst) const
//{
//	auto key = std::make_tuple(pointee, isVolatile, isConst);
//	return retdec::utils::mapHasKey(pointerTypes, key);
//}
//
//std::shared_ptr<PointerTypeNode> Context::getPointerType(
//	std::shared_ptr<retdec::demangler::borland::Node> pointee, bool isVolatile, bool isConst) const
//{
//	auto key = std::make_tuple(pointee, isVolatile, isConst);
//	return retdec::utils::mapGetValueOrDefault(pointerTypes, key);
//}
//
//void Context::addPointerType(const std::shared_ptr<retdec::demangler::borland::PointerTypeNode> &type)
//{
//	assert(type && "violated precondition - type cannot be null");
//
//	auto key = std::make_tuple(type->pointee(), type->isVolatile(), type->isConst());
//	pointerTypes.emplace(key, type);
//}
//
//bool Context::hasReferenceType(std::shared_ptr<retdec::demangler::borland::Node> pointee) const
//{
//	return retdec::utils::mapHasKey(referenceTypes, pointee);
//}
//
//std::shared_ptr<ReferenceTypeNode> Context::getReferenceType(std::shared_ptr<Node> pointee) const
//{
//	return retdec::utils::mapGetValueOrDefault(referenceTypes, pointee);
//}
//
//void Context::addReferenceType(const std::shared_ptr<ReferenceTypeNode> &type)
//{
//	assert(type && "violated precondition - type cannot be null");
//
//	referenceTypes.emplace(type->pointee(), type);
//}
//
//bool Context::hasNamedType(const StringView &name, bool isVolatile, bool isConst) const
//{
//	std::string name_str = std::string{name.begin(), name.size()};
//	auto key = std::make_tuple(name_str, isVolatile, isConst);
//	return retdec::utils::mapHasKey(namedTypes, key);
//}
//
//std::shared_ptr<NamedTypeNode> Context::getNamedType(const StringView &name, bool isVolatile, bool isConst) const
//{
//	std::string name_str = std::string{name.begin(), name.size()};
//	auto key = std::make_tuple(name_str, isVolatile, isConst);
////	return std::static_pointer_cast<NamedTypeNode>(retdec::utils::mapGetValueOrDefault(namedTypes, key));
//	return retdec::utils::mapGetValueOrDefault(namedTypes, key);
//}
//
//void Context::addNamedType(const std::shared_ptr<retdec::demangler::borland::NamedTypeNode> &type)
//{
//	assert(type && "violated precondition - type cannot be null");
//
//	auto name = type->typeName();
//	std::string name_str = std::string{name.begin(), name.size()};
//	auto key = std::make_tuple(name_str, type->isVolatile(), type->isConst());
//
//	namedTypes.emplace(key, type);
//}

}    // borland
}    // demangler
}    // retdec

