
#include "retdec/bin2llvmir/providers/lti.h"
#include "retdec/bin2llvmir/utils/ctypes2llvm.h"
#include "retdec/ctypes/ctypes.h"
#include "retdec/utils/string.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

Ctypes2LlvmTypeVisitor::Ctypes2LlvmTypeVisitor(llvm::Module *m, Config *c) :
	_module(m),
	_config(c)
{
	assert(_module);
	assert(_config);
	_type = Abi::getDefaultType(_module);
}

void Ctypes2LlvmTypeVisitor::visit(
	const std::shared_ptr <retdec::ctypes::ArrayType> &type)
{
	type->getElementType()->accept(this);

	auto &dims = type->getDimensions();
	for (auto it = dims.rbegin(); it != dims.rend(); ++it) {
		auto *t = ArrayType::isValidElementType(_type) ?
				  _type : Abi::getDefaultType(_module);
		auto d = *it > 0 ? *it : 1;
		_type = ArrayType::get(t, d);
	}
}

void Ctypes2LlvmTypeVisitor::visit(
	const std::shared_ptr <retdec::ctypes::EnumType> &type)
{
	_type = Abi::getDefaultType(_module);
}

void Ctypes2LlvmTypeVisitor::visit(
	const std::shared_ptr <retdec::ctypes::FloatingPointType> &type)
{
	auto &ctx = _module->getContext();
	switch (type->getBitWidth()) {
	case 16:
		_type = Type::getHalfTy(ctx);
		break;
	case 32:
		_type = Type::getFloatTy(ctx);
		break;
	case 64:
		_type = Type::getDoubleTy(ctx);
		break;
	case 80:
		_type = Type::getX86_FP80Ty(ctx);
		break;
	case 128:
		_type = Type::getFP128Ty(ctx);
		break;
	default:
		_type = Type::getFloatTy(ctx);
		break;
	}
}

void Ctypes2LlvmTypeVisitor::visit(
	const std::shared_ptr <retdec::ctypes::FunctionType> &type)
{
	type->getReturnType()->accept(this);
	auto *ret = FunctionType::isValidReturnType(_type) ?
				_type : Abi::getDefaultType(_module);

	std::vector < Type * > params;
	params.reserve(type->getParameterCount());
	for (const auto &param: type->getParameters()) {
		param->accept(this);
		if (type->getParameterCount() == 1 && _type->isVoidTy()) {
			// pass -> sometimes signatures in ctypesl have one param like this:
			// function(void)
		} else {
			auto *t = FunctionType::isValidArgumentType(_type) ?
					  _type : Abi::getDefaultType(_module);
			params.push_back(t);
		}
	}

	_type = FunctionType::get(
		ret,
		params,
		type->isVarArg());
}

void Ctypes2LlvmTypeVisitor::visit(
	const std::shared_ptr <retdec::ctypes::IntegralType> &type)
{
	auto tsz = type->getBitWidth();
	assert(tsz);
	auto sz = tsz ? tsz : Abi::getDefaultType(_module)->getBitWidth();
	_type = Type::getIntNTy(_module->getContext(), sz);
}

void Ctypes2LlvmTypeVisitor::visit(
	const std::shared_ptr <retdec::ctypes::NamedType> &type)
{
	// known classes (std::string, ...) could be created based on typename
	// and pointer to them returned
	_type = Abi::getDefaultType(_module);
}

void Ctypes2LlvmTypeVisitor::visit(
	const std::shared_ptr <retdec::ctypes::PointerType> &type)
{
	type->getPointedType()->accept(this);

	auto *t = PointerType::isValidElementType(_type) ?
			  _type : Abi::getDefaultType(_module);
	_type = PointerType::get(t, 0);
}

void Ctypes2LlvmTypeVisitor::visit(
	const std::shared_ptr <retdec::ctypes::ReferenceType> &type)
{
	// in LLVM IR reference parameter is implemented as pointer with attribute dereferenceable
	// this attribute must be set when creating llvm::Function and can't be set here
	type->getReferencedType()->accept(this);

	auto *t = PointerType::isValidElementType(_type) ?
			  _type : Abi::getDefaultType(_module);
	_type = PointerType::get(t, 0);
}

void Ctypes2LlvmTypeVisitor::visit(
	const std::shared_ptr <retdec::ctypes::TypedefedType> &type)
{
	if (retdec::utils::containsCaseInsensitive(type->getName(), "wchar")) {	// TODO remove and unify with lti
		// getDefaultWchartType()?
		if (_config->getConfig().fileFormat.isElf()) {
			_type = Type::getInt32Ty(_module->getContext());
		} else if (_config->getConfig().fileFormat.isPe()) {
			_type = Type::getInt16Ty(_module->getContext());
		} else {
			_type = Type::getInt16Ty(_module->getContext());
		}
		return;
	} else if (type->getName() == "BOOL") {
		_type = Type::getInt1Ty(_module->getContext());
		return;
	}

	type->getAliasedType()->accept(this);
}

void Ctypes2LlvmTypeVisitor::visit(
	const std::shared_ptr <retdec::ctypes::UnionType> &type)
{
	_type = Abi::getDefaultType(_module);
}

void Ctypes2LlvmTypeVisitor::visit(
	const std::shared_ptr <retdec::ctypes::UnknownType> &type)
{
	_type = Abi::getDefaultType(_module);
}

void Ctypes2LlvmTypeVisitor::visit(
	const std::shared_ptr <retdec::ctypes::VoidType> &type)
{
	_type = Type::getVoidTy(_module->getContext());
}

void Ctypes2LlvmTypeVisitor::visit(
	const std::shared_ptr <retdec::ctypes::StructType> &type)
{
	std::string name = type->getName();
	std::string prefix = "struct ";
	if (retdec::utils::startsWith(name, prefix))
	{
		name.erase(0, prefix.length());
	}

	if (auto *ex = _module->getTypeByName(name)) {
		_type = ex;
		return;
	}

	auto *opaqStr = StructType::create(_module->getContext(), name);

	std::vector < Type * > elems;
	elems.reserve(type->getMemberCount());
	for (auto i = type->member_begin(), e = type->member_end(); i != e; ++i) {
		i->getType()->accept(this);

		auto *t = StructType::isValidElementType(_type) ?
				  _type : Abi::getDefaultType(_module);
		elems.push_back(t);
	}
	if (elems.empty()) {
		elems.push_back(Type::getInt32Ty(_module->getContext()));
	}

	// After body is set, structure is no long opaq.
	opaqStr->setBody(elems);
	_type = opaqStr;
}

Type *Ctypes2LlvmTypeVisitor::getLlvmType() const
{
	return _type;
}

}	// namespace bin2llvmir
}	// namespace retdec
