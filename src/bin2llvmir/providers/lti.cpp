/**
 * @file src/bin2llvmir/providers/lti.cpp
 * @brief Library type information provider for bin2llvmirl.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <fstream>

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
#include "retdec/bin2llvmir/utils/ctypes2llvm.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

//
//=============================================================================
//  Lti
//=============================================================================
//

Lti::Lti(
	llvm::Module *m,
	Config *c,
	const std::shared_ptr<ctypesparser::TypeConfig> &typeConfig,
	retdec::loader::Image *objf)
		:
		_module(m),
		_config(c),
		_typeConfig(typeConfig),
		_image(objf)
{
	_ltiModule = std::make_unique<retdec::ctypes::Module>(
			std::make_shared<retdec::ctypes::Context>());

	_ltiParser = ctypesparser::JSONCTypesParser(
			static_cast<unsigned>(c->getConfig().architecture.getBitSize()));

	for (auto& l : _config->getConfig().parameters.libraryTypeInfoPaths)
	{
		if (retdec::utils::endsWith(l, "cstdlib.json"))
		{
			loadLtiFile(l);
		}
	}

	bool winDriver = _image->getFileFormat()->isWindowsDriver();

	for (auto &l : _config->getConfig().parameters.libraryTypeInfoPaths)
	{
		if (retdec::utils::endsWith(l, "cstdlib.json"))
		{
			continue;
		}

		if (retdec::utils::endsWith(l, "windows.json")
				&& _config->getConfig().fileFormat.isPe())
		{
			loadLtiFile(l);
		}
		else if (winDriver
				&& retdec::utils::endsWith(l, "windrivers.json"))
		{
			loadLtiFile(l);
		}
		else if (retdec::utils::endsWith(l, "linux.json")
				&& (_config->getConfig().fileFormat.isElf()
				|| _config->getConfig().fileFormat.isMacho()
				|| _config->getConfig().fileFormat.isIntelHex()
				|| _config->getConfig().fileFormat.isRaw()))
		{
			loadLtiFile(l);
		}
		else if (retdec::utils::endsWith(l, "arm.json") &&
				_config->getConfig().architecture.isArm32OrThumb())
		{
			loadLtiFile(l);
		}
	}
}

void Lti::loadLtiFile(const std::string& filePath)
{
	std::ifstream file(filePath);
	if (file)
	{
		std::string cc = "cdecl";
		if (retdec::utils::containsCaseInsensitive(filePath, "win"))
		{
			cc = "stdcall";
		}
		_ltiParser.parseInto(file, _ltiModule, _typeConfig->typeWidths(), cc);
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

	assert(ltiFnc->getParameterCount() == ret->arg_size()
			|| (ltiFnc->getParameterCount() == 1
					&& ret->arg_empty()
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

		// TODO: this is really bad, should be solved by better design of config
		// updates
		common::Function* cf = const_cast<common::Function*>(
				_config->insertFunction(ret.first));
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
	Ctypes2LlvmTypeVisitor visitor(_module, _config);
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
	llvm::Module *m,
	Config *c,
	const std::shared_ptr<ctypesparser::TypeConfig> &typeConfig,
	retdec::loader::Image *objf)
{
	if (m == nullptr || c == nullptr || objf == nullptr)
	{
		return nullptr;
	}

	auto p = _module2lti.emplace(m, Lti(m, c, typeConfig, objf));
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
