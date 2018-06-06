/**
 * @file src/bin2llvmir/providers/lti.cpp
 * @brief Library type information provider for bin2llvmirl.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <fstream>
#include <iostream>

#include "retdec/ctypes/floating_point_type.h"
#include "retdec/ctypes/function_type.h"
#include "retdec/ctypes/integral_type.h"
#include "retdec/ctypes/member.h"
#include "retdec/ctypes/pointer_type.h"
#include "retdec/ctypes/struct_type.h"
#include "retdec/ctypes/typedefed_type.h"
#include "retdec/ctypes/union_type.h"
#include "retdec/ctypes/unknown_type.h"
#include "retdec/ctypes/void_type.h"
#include "retdec/utils/string.h"
#include "retdec/bin2llvmir/providers/lti.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

//
//=============================================================================
//  ToLlvmTypeVisitor
//=============================================================================
//

ToLlvmTypeVisitor::ToLlvmTypeVisitor(llvm::Module* m, Config* c) :
		_module(m),
		_config(c)
{
	assert(_module);
	assert(_config);
	_type = Abi::getDefaultType(_module);
}

ToLlvmTypeVisitor::~ToLlvmTypeVisitor() = default;

void ToLlvmTypeVisitor::visit(
		const std::shared_ptr<retdec::ctypes::ArrayType>& type)
{
	type->getElementType()->accept(this);

	auto& dims = type->getDimensions();
	for (auto it = dims.rbegin(); it != dims.rend(); ++it)
	{
		auto* t = ArrayType::isValidElementType(_type) ?
				_type : Abi::getDefaultType(_module);
		auto d = *it > 0 ? *it : 1;
		_type = ArrayType::get(t, d);
	}
}

void ToLlvmTypeVisitor::visit(
		const std::shared_ptr<retdec::ctypes::EnumType>& type)
{
	_type = Abi::getDefaultType(_module);
}

void ToLlvmTypeVisitor::visit(
		const std::shared_ptr<retdec::ctypes::FloatingPointType>& type)
{
	auto& ctx = _module->getContext();
	switch (type->getBitWidth())
	{
		case 16: _type = Type::getHalfTy(ctx); break;
		case 32: _type = Type::getFloatTy(ctx); break;
		case 64: _type = Type::getDoubleTy(ctx); break;
		case 80: _type = Type::getX86_FP80Ty(ctx); break;
		case 128: _type = Type::getFP128Ty(ctx); break;
		default: _type = Type::getFloatTy(ctx); break;
	}
}

void ToLlvmTypeVisitor::visit(
		const std::shared_ptr<retdec::ctypes::FunctionType>& type)
{
	type->getReturnType()->accept(this);
	auto* ret = FunctionType::isValidReturnType(_type) ?
			_type : Abi::getDefaultType(_module);

	std::vector<Type*> params;
	params.reserve(type->getParameterCount());
	for (const auto& param: type->getParameters())
	{
		param->accept(this);
		if (type->getParameterCount() == 1 && _type->isVoidTy())
		{
			// pass -> sometimes signatures in ctypesl have one param like this:
			// function(void)
		}
		else
		{
			auto* t = FunctionType::isValidArgumentType(_type) ?
					_type : Abi::getDefaultType(_module);
			params.push_back(t);
		}
	}

	_type = FunctionType::get(
			ret,
			params,
			type->isVarArg());
}

void ToLlvmTypeVisitor::visit(
		const std::shared_ptr<retdec::ctypes::IntegralType>& type)
{
	auto tsz = type->getBitWidth();
	assert(tsz);
	auto sz = tsz ? tsz : Abi::getDefaultType(_module)->getBitWidth();
	_type = Type::getIntNTy(_module->getContext(), sz);
}

void ToLlvmTypeVisitor::visit(
		const std::shared_ptr<retdec::ctypes::PointerType>& type)
{
	type->getPointedType()->accept(this);

	auto* t = PointerType::isValidElementType(_type) ?
			_type : Abi::getDefaultType(_module);
	_type = PointerType::get(t, 0);
}

void ToLlvmTypeVisitor::visit(
		const std::shared_ptr<retdec::ctypes::TypedefedType>& type)
{
	if (retdec::utils::containsCaseInsensitive(type->getName(), "wchar"))
	{
		// getDefaultWchartType()?
		if (_config->getConfig().fileFormat.isElf())
		{
			_type = Type::getInt32Ty(_module->getContext());
		}
		else if (_config->getConfig().fileFormat.isPe())
		{
			_type = Type::getInt16Ty(_module->getContext());
		}
		else
		{
			_type = Type::getInt16Ty(_module->getContext());
		}
		return;
	}
	else if (type->getName() == "BOOL")
	{
		_type = Type::getInt1Ty(_module->getContext());
		return;
	}

	type->getAliasedType()->accept(this);
}

void ToLlvmTypeVisitor::visit(
		const std::shared_ptr<retdec::ctypes::UnionType>& type)
{
	_type = Abi::getDefaultType(_module);
}

void ToLlvmTypeVisitor::visit(
		const std::shared_ptr<retdec::ctypes::UnknownType>& type)
{
	_type = Abi::getDefaultType(_module);
}

void ToLlvmTypeVisitor::visit(
		const std::shared_ptr<retdec::ctypes::VoidType>& type)
{
	_type = Type::getVoidTy(_module->getContext());
}

void ToLlvmTypeVisitor::visit(
		const std::shared_ptr<retdec::ctypes::StructType>& type)
{
	std::string name = type->getName();
	std::string prefix = "struct ";
	if (retdec::utils::startsWith(name, prefix))
	{
		name.erase(0, prefix.length());
	}

	if (auto* ex = _module->getTypeByName(name))
	{
		_type = ex;
		return;
	}

	auto* opaqStr = StructType::create(_module->getContext(), name);

	std::vector<Type*> elems;
	elems.reserve(type->getMemberCount());
	for (auto i = type->member_begin(), e = type->member_end(); i != e; ++i)
	{
		i->getType()->accept(this);

		auto* t = StructType::isValidElementType(_type) ?
				_type : Abi::getDefaultType(_module);
		elems.push_back(t);
	}
	if (elems.empty())
	{
		elems.push_back(Type::getInt32Ty(_module->getContext()));
	}

	// After body is set, structure is no long opaq.
	opaqStr->setBody(elems);
	_type = opaqStr;
}

Type* ToLlvmTypeVisitor::getLlvmType() const
{
	return _type;
}

//
//=============================================================================
//  Lti
//=============================================================================
//

Lti::Lti(
		llvm::Module* m,
		Config* c,
		retdec::loader::Image* objf)
		:
		_module(m),
		_config(c),
		_image(objf)
{
	_ltiModule = std::make_unique<retdec::ctypes::Module>(
			std::make_shared<retdec::ctypes::Context>());

	_ltiParser = ctypesparser::JSONCTypesParser(
			static_cast<unsigned>(c->getConfig().architecture.getBitSize()));

	for (auto& l : _config->getConfig().parameters.libraryTypeInfoPaths)
	{
		if (retdec::utils::startsWith(retdec::utils::stripDirs(l), "cstdlib"))
		{
			loadLtiFile(l);
		}
	}

	bool winDriver = _image->getFileFormat()->isWindowsDriver();

	for (auto &l : _config->getConfig().parameters.libraryTypeInfoPaths)
	{
		auto fileName = retdec::utils::stripDirs(l);

		if (retdec::utils::startsWith(fileName, "cstdlib"))
		{
			continue;
		}

		if (retdec::utils::startsWith(fileName, "windows")
				&& _config->getConfig().fileFormat.isPe())
		{
			loadLtiFile(l);
		}
		else if (winDriver
				&& retdec::utils::startsWith(fileName, "windrivers"))
		{
			loadLtiFile(l);
		}
		else if (retdec::utils::startsWith(fileName, "linux")
				&& (_config->getConfig().fileFormat.isElf()
				|| _config->getConfig().fileFormat.isMacho()
				|| _config->getConfig().fileFormat.isIntelHex()
				|| _config->getConfig().fileFormat.isRaw()))
		{
			loadLtiFile(l);
		}
		else if (retdec::utils::startsWith(fileName, "arm") &&
				_config->getConfig().architecture.isArmOrThumb())
		{
			loadLtiFile(l);
		}
	}
}

void Lti::loadLtiFile(const std::string& filePath)
{
	// This could/should be derived from architecture or LLVM module.
	//
	static ctypesparser::JSONCTypesParser::TypeWidths typeWidths
	{
		{"bool", 1},
		{"char", 8},
		{"short", 16},
		{"int", 32},
		{"long", 32},
		{"long long", 64},
		{"float", 32},
		{"double", 64},
		{"long double", 80},

		// more exotic types: should be solved by ctypesparserl
		{"unsigned __int64", 64},
		{"unsigned __int16", 16},
		{"unsigned __int32", 32},
		{"unsigned __int3264", 32} // this has the same size as arch size
	};

	std::ifstream file(filePath);
	if (file)
	{
		std::string cc = "cdecl";
		if (retdec::utils::containsCaseInsensitive(filePath, "win"))
		{
			cc = "stdcall";
		}
		_ltiParser.parseInto(file, _ltiModule, typeWidths, cc);
	}
}

bool Lti::hasLtiFunction(const std::string& name)
{
	return getLtiFunction(name) != nullptr;
}

std::shared_ptr<retdec::ctypes::Function> Lti::getLtiFunction(
		const std::string& name)
{
	return _ltiModule->getFunctionWithName(name);
}

/**
 * Find LTI function with @c name and get its LLVM type.
 * @param[in]  name   Function name to find.
 * @return LLVM function type for @c name, or @c nullptr if not found.
 */
llvm::FunctionType* Lti::getLlvmFunctionType(const std::string& name)
{
	auto ltiFnc = getLtiFunction(name);
	if (ltiFnc == nullptr)
	{
		return nullptr;
	}

	auto* ft = dyn_cast<FunctionType>(getLlvmType(ltiFnc->getType()));
	assert(ft);

	std::string declaration = ltiFnc->getDeclaration();
	if (declaration.find("...") != std::string::npos
			&& !ft->isVarArg())
	{
		ft = FunctionType::get(ft->getReturnType(), ft->params(), true);
	}

	return ft;
}

Lti::FunctionPair Lti::getPairFunctionFree(const std::string& n)
{
	std::string name = n;
	auto ltiFnc = getLtiFunction(name);
	if (ltiFnc == nullptr)
	{
		name = retdec::utils::removeLeadingCharacter(name, '_');
		ltiFnc = getLtiFunction(name);
	}
	if (ltiFnc == nullptr)
	{
		std::shared_ptr<retdec::ctypes::Function> sp(nullptr);
		return {nullptr, sp};
	}
	auto* ft = getLlvmFunctionType(name);
	assert(ft);

	auto* ret = Function::Create(
			ft,
			GlobalValue::ExternalLinkage,
			name);

	assert(ltiFnc->getParameterCount() == ret->getArgumentList().size()
			|| (ltiFnc->getParameterCount() == 1
					&& ret->getArgumentList().empty()
					&& getLlvmType(ltiFnc->getParameterType(1))->isVoidTy()));
	std::size_t i = 1;
	std::size_t e = ltiFnc->getParameterCount();
	for (auto a = ret->arg_begin(), ae = ret->arg_end(); a != ae; ++a, ++i)
	{
		if (i <= e)
		{
			a->setName(ltiFnc->getParameterName(i));
		}
		else
		{
			a->setName("arg" + std::to_string(i));
		}
	}

	return {ret, ltiFnc};
}

llvm::Function* Lti::getLlvmFunctionFree(const std::string& name)
{
	return getPairFunctionFree(name).first;
}

Lti::FunctionPair Lti::getPairFunction(const std::string& name)
{
	auto ret = getPairFunctionFree(name);
	if (ret.first)
	{
		auto* exLlvm = _module->getFunction(name);
		if (exLlvm)
		{
			assert(ret.first->getFunctionType() == exLlvm->getFunctionType());
			return {exLlvm, ret.second};
		}

		_module->getFunctionList().insert(
				_module->getFunctionList().end(),
				ret.first);

		auto* cf = _config->insertFunction(ret.first);
		cf->setDeclarationString(ret.second->getDeclaration());
	}

	return ret;
}

llvm::Function* Lti::getLlvmFunction(const std::string& name)
{
	return getPairFunction(name).first;
}

llvm::Type* Lti::getLlvmType(std::shared_ptr<retdec::ctypes::Type> type)
{
	ToLlvmTypeVisitor visitor(_module, _config);
	type->accept(&visitor);
	return visitor.getLlvmType();
}

//
//=============================================================================
//  LtiProvider
//=============================================================================
//

std::map<llvm::Module*, Lti> LtiProvider::_module2lti;

Lti* LtiProvider::addLti(
		llvm::Module* m,
		Config* c,
		retdec::loader::Image* objf)
{
	if (m == nullptr || c == nullptr || objf == nullptr)
	{
		return nullptr;
	}

	auto p = _module2lti.emplace(m, Lti(m, c, objf));
	return &p.first->second;
}

Lti* LtiProvider::getLti(llvm::Module* m)
{
	auto f = _module2lti.find(m);
	return f != _module2lti.end() ? &f->second : nullptr;
}

bool LtiProvider::getLti(llvm::Module* m, Lti*& lti)
{
	lti = getLti(m);
	return lti != nullptr;
}

void LtiProvider::clear()
{
	_module2lti.clear();
}

} // namespace bin2llvmir
} // namespace retdec
