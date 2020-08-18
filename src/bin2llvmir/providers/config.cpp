/**
 * @file src/bin2llvmir/providers/config.cpp
 * @brief Config DB provider for bin2llvmirl.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <llvm/IR/GlobalVariable.h>
#include <llvm/IR/Module.h>

#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/providers/demangler.h"
#include "retdec/bin2llvmir/utils/debug.h"
#include "retdec/bin2llvmir/utils/llvm.h"
#include "retdec/utils/string.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

//
//=============================================================================
//  Config
//=============================================================================
//

retdec::config::Config _emptyConfig;

Config::Config(retdec::config::Config& c)
		: _configDB(c)
{

}

Config Config::empty(llvm::Module* m)
{
	_emptyConfig = retdec::config::Config();
	Config config(_emptyConfig);
	config._module = m;
	return config;
}

Config Config::fromConfig(llvm::Module* m, retdec::config::Config& c)
{
	Config config(c);
	config._module = m;

	// Create all structures defined in the config.
	//
	for (auto& s : config.getConfig().structures)
	{
		llvm_utils::stringToLlvmType(m->getContext(), s.getLlvmIr());
	}

	// TODO: needed?
	if (config.getConfig().tools.isPic32())
	{
		config.getConfig().architecture.setIsPic32();
	}

	return config;
}

/**
 * Save the config to reflect changes that have been done to it in
 * the bin2llvmirl.
 */
void Config::doFinalization()
{
	tagFunctionsWithUsedCryptoGlobals();

	if (!_configDB.parameters.getOutputConfigFile().empty())
	{
		_configDB.generateJsonFile(_configDB.parameters.getOutputConfigFile());
	}
}

retdec::config::Config& Config::getConfig()
{
	return _configDB;
}

const retdec::config::Config& Config::getConfig() const
{
	return _configDB;
}

llvm::Function* Config::getLlvmFunction(common::Address startAddr)
{
	auto fnc = getConfigFunction(startAddr);
	return fnc ? _module->getFunction(fnc->getName()) : nullptr;
}

retdec::common::Address Config::getFunctionAddress(
		const llvm::Function* fnc)
{
	retdec::common::Function* cf = getConfigFunction(fnc);
	return cf ? cf->getStart() : retdec::common::Address();
}

retdec::common::Function* Config::getConfigFunction(
		const llvm::Function* fnc)
{
	// TODO: remove horrible const_cast
	return fnc
		? const_cast<retdec::common::Function*>(
				_configDB.functions.getFunctionByName(fnc->getName()))
		: nullptr;
}

retdec::common::Function* Config::getConfigFunction(
		retdec::common::Address startAddr)
{
	// TODO: remove horrible const_cast
	return const_cast<retdec::common::Function*>(
			_configDB.functions.getFunctionByStartAddress(startAddr));
}

llvm::Function* Config::getIntrinsicFunction(IntrinsicFunctionCreatorPtr f)
{
	auto fit = _intrinsicFunctions.find(f);
	if (fit != _intrinsicFunctions.end())
	{
		return fit->second;
	}
	else
	{
		auto* intrinsic = f(_module);
		_intrinsicFunctions[f] = intrinsic;
		return intrinsic;
	}
}

const retdec::common::Object* Config::getConfigGlobalVariable(
		const llvm::GlobalVariable* gv)
{
	return gv ? _configDB.globals.getObjectByName(gv->getName()) : nullptr;
}

const retdec::common::Object* Config::getConfigGlobalVariable(
		retdec::common::Address address)
{
	return _configDB.globals.getObjectByAddress(address);
}

llvm::GlobalVariable* Config::getLlvmGlobalVariable(common::Address address)
{
	auto glob = _configDB.globals.getObjectByAddress(address);
	return glob ? _module->getGlobalVariable(glob->getName()) : nullptr;
}

/**
 * Global variables have two unique IDs -- name and address. This method returns
 * LLVM global with either @a name (string search in module's globals) or
 * @a address (config used to get global by address).
 */
llvm::GlobalVariable* Config::getLlvmGlobalVariable(
		const std::string& name,
		retdec::common::Address address)
{
	if (auto* gv = _module->getGlobalVariable(name))
	{
		return gv;
	}
	else if (auto* gv = getLlvmGlobalVariable(address))
	{
		return gv;
	}
	else
	{
		return nullptr;
	}
}

retdec::common::Address Config::getGlobalAddress(
		const llvm::GlobalVariable* gv)
{
	assert(gv);
	auto* cgv = gv ? _configDB.globals.getObjectByName(gv->getName()) : nullptr;
	return cgv ? cgv->getStorage().getAddress() : retdec::common::Address();
}

bool Config::isGlobalVariable(const llvm::Value* val)
{
	auto* gv = dyn_cast<GlobalVariable>(val);
	return getConfigGlobalVariable(gv) != nullptr;
}

const retdec::common::Object* Config::getConfigLocalVariable(
		const llvm::Value* val)
{
	auto* a = dyn_cast_or_null<AllocaInst>(val);
	if (a == nullptr)
	{
		return nullptr;
	}
	auto* cf = getConfigFunction(a->getFunction());
	if (cf == nullptr)
	{
		return nullptr;
	}
	auto* cl = cf->locals.getObjectByName(a->getName());
	return cl && cl->getStorage().isUndefined() ? cl : nullptr;
}

retdec::common::Object* Config::getConfigStackVariable(
		const llvm::Value* val)
{
	auto* a = dyn_cast_or_null<AllocaInst>(val);
	if (a == nullptr)
	{
		return nullptr;
	}
	auto* cf = getConfigFunction(a->getFunction());
	if (cf == nullptr)
	{
		return nullptr;
	}
	auto* cl = const_cast<retdec::common::Object*>(
			cf->locals.getObjectByName(a->getName()));
	return cl && cl->getStorage().isStack() ? cl : nullptr;
}

/**
 * @return LLVM alloca instruction for stack variable with offset @a offset in
 *         function @a fnc. @c nullptr if such variable does not exist.
 */
llvm::AllocaInst* Config::getLlvmStackVariable(
		llvm::Function* fnc,
		int offset)
{
	auto* cf = getConfigFunction(fnc);
	if (cf == nullptr)
	{
		return nullptr;
	}

	for (auto& l: cf->locals)
	{
		int off = 0;
		if (l.getStorage().isStack(off) && off == offset)
		{
			for (auto& b : *fnc)
			for (auto& i : b)
			{
				if (AllocaInst* a = dyn_cast<AllocaInst>(&i))
				{
					if (a->getName() == l.getName())
					{
						return a;
					}
				}
			}
		}
	}

	return nullptr;
}

llvm::AllocaInst* Config::getLlvmStackVariable(
		llvm::Function* fnc,
		const std::string& realName)
{
	auto* cf = getConfigFunction(fnc);
	if (cf == nullptr)
	{
		return nullptr;
	}

	for (auto& l: cf->locals)
	{
		if (l.getRealName() == realName)
		{
			for (auto& b : *fnc)
			for (auto& i : b)
			{
				if (AllocaInst* a = dyn_cast<AllocaInst>(&i))
				{
					if (a->getName() == l.getName())
					{
						return a;
					}
				}
			}
		}
	}

	return nullptr;
}

/**
 * @return @c True if the the provided LLVM value @a val is a stack variable.
 *         @c False otherwise.
 */
bool Config::isStackVariable(const llvm::Value* val)
{
	return getConfigStackVariable(val) != nullptr;
}

std::optional<int> Config::getStackVariableOffset(
		const llvm::Value* val)
{
	auto* sv = getConfigStackVariable(val);
	return sv
			? std::optional<int>(sv->getStorage().getStackOffset())
			: std::nullopt;
}

const retdec::common::Object* Config::insertGlobalVariable(
		const llvm::GlobalVariable* gv,
		retdec::common::Address address,
		bool fromDebug,
		const std::string& realName,
		const std::string& cryptoDesc)
{
	retdec::common::Object cgv(
			gv->getName(),
			retdec::common::Storage::inMemory(address));
	cgv.setIsFromDebug(fromDebug);
	cgv.setRealName(realName);
	cgv.setCryptoDescription(cryptoDesc);
	cgv.type.setLlvmIr(llvmObjToString(gv->getType()->getElementType()));
	if (gv->hasInitializer() && gv->getInitializer()->getName() == "wide-string")
	{
		cgv.type.setIsWideString(true);
	}
	auto p = _configDB.globals.insert(cgv);

	return &(*p.first);
}

const retdec::common::Object* Config::insertStackVariable(
		const llvm::AllocaInst* sv,
		int offset,
		bool fromDebug,
		const std::string& realName)
{
	auto* cf = getConfigFunction(sv->getFunction());

	if (cf == nullptr)
	{
		assert(false);
	}

	assert(cf);
	if (cf == nullptr)
	{
		return nullptr;
	}

	retdec::common::Object local(
			sv->getName(),
			retdec::common::Storage::onStack(offset));
	if (realName.empty())
	{
		local.setRealName(sv->getName());
	}
	else
	{
		local.setRealName(realName);
	}
	local.setIsFromDebug(fromDebug);
	local.type.setLlvmIr(llvmObjToString(sv->getType()));

	auto p = cf->locals.insert(local);
	return &(*p.first);
}

const retdec::common::Function* Config::insertFunction(
		const llvm::Function* fnc,
		retdec::common::Address start,
		retdec::common::Address end,
		bool fromDebug)
{
	std::string dm;
	if (auto* old = getConfigFunction(start))
	{
		dm = old->getDemangledName();
	}

	retdec::common::Function cf(fnc->getName());
	cf.setDemangledName(dm);
	cf.setIsFromDebug(fromDebug);
	cf.setStartEnd(start, end);

	if (cf.getDemangledName().empty())
	{
		Demangler* d = DemanglerProvider::getDemangler(_module);
		if (d)
		{
			auto s = d->demangleToString(fnc->getName());
			if (!s.empty())
			{
				cf.setDemangledName(s);
			}
		}
	}

	auto p = _configDB.functions.insert(cf);
	return &(*p.first);
}

retdec::common::Function* Config::renameFunction(
		retdec::common::Function* fnc,
		const std::string& name)
{
	retdec::common::Function cf = *fnc;
	cf.setName(name);

	if (cf.getDemangledName().empty())
	{
		Demangler* d = DemanglerProvider::getDemangler(_module);
		if (d)
		{
			auto s = d->demangleToString(fnc->getName());
			if (!s.empty())
			{
				cf.setDemangledName(s);
			}
		}
	}

	_configDB.functions.erase(fnc->getName());
	auto p = _configDB.functions.insert(cf);

	// TODO: remove horrible const_cast
	return const_cast<retdec::common::Function*>(&(*p.first));
}

const retdec::common::Object* Config::getConfigRegister(
		const llvm::Value* val)
{
	auto* gv = dyn_cast_or_null<GlobalVariable>(val);
	return gv ? _configDB.registers.getObjectByName(gv->getName()) : nullptr;
}

std::optional<unsigned> Config::getConfigRegisterNumber(
		const llvm::Value* val)
{
	std::optional<unsigned> undefVal;
	auto* r = getConfigRegister(val);
	return r ? r->getStorage().getRegisterNumber() : undefVal;
}

/**
 * @return Always returns the same dummy global variable.
 */
llvm::GlobalVariable* Config::getGlobalDummy()
{
	if (_globalDummy == nullptr)
	{
		_globalDummy = new GlobalVariable(
				*_module,
				Type::getInt32Ty(_module->getContext()),
				false,
				GlobalValue::ExternalLinkage,
				nullptr);
		assert(_globalDummy);
	}
	return _globalDummy;
}

fs::path Config::getOutputDirectory()
{
	fs::path fsp(getConfig().parameters.getOutputFile());
	return fs::canonical(fsp).parent_path();
}

void Config::setLlvmCallPseudoFunction(llvm::Function* f)
{
	_callFunction = f;
}
llvm::Function* Config::getLlvmCallPseudoFunction() const
{
	return _callFunction;
}
bool Config::isLlvmCallPseudoFunction(llvm::Value* f)
{
	return _callFunction == f;
}
llvm::CallInst* Config::isLlvmCallPseudoFunctionCall(llvm::Value* c)
{
	auto* cc = dyn_cast_or_null<CallInst>(c);
	return cc && cc->getCalledValue() == _callFunction ? cc : nullptr;
}

void Config::setLlvmReturnPseudoFunction(llvm::Function* f)
{
	_returnFunction = f;
}
llvm::Function* Config::getLlvmReturnPseudoFunction() const
{
	return _returnFunction;
}
bool Config::isLlvmReturnPseudoFunction(llvm::Value* f)
{
	return _returnFunction == f;
}
llvm::CallInst* Config::isLlvmReturnPseudoFunctionCall(llvm::Value* c)
{
	auto* cc = dyn_cast_or_null<CallInst>(c);
	return cc && cc->getCalledValue() == _returnFunction ? cc : nullptr;
}

void Config::setLlvmBranchPseudoFunction(llvm::Function* f)
{
	_branchFunction = f;
}
llvm::Function* Config::getLlvmBranchPseudoFunction() const
{
	return _branchFunction;
}
bool Config::isLlvmBranchPseudoFunction(llvm::Value* f)
{
	return _branchFunction == f;
}
llvm::CallInst* Config::isLlvmBranchPseudoFunctionCall(llvm::Value* c)
{
	auto* cc = dyn_cast_or_null<CallInst>(c);
	return cc && cc->getCalledValue() == _branchFunction ? cc : nullptr;
}

void Config::setLlvmCondBranchPseudoFunction(llvm::Function* f)
{
	_condBranchFunction = f;
}
llvm::Function* Config::getLlvmCondBranchPseudoFunction() const
{
	return _condBranchFunction;
}
bool Config::isLlvmCondBranchPseudoFunction(llvm::Value* f)
{
	return _condBranchFunction == f;
}
llvm::CallInst* Config::isLlvmCondBranchPseudoFunctionCall(llvm::Value* c)
{
	auto* cc = dyn_cast_or_null<CallInst>(c);
	return cc && cc->getCalledValue() == _condBranchFunction ? cc : nullptr;
}

void Config::setLlvmX87DataStorePseudoFunction(llvm::Function* f)
{
	_x87DataStoreFunction = f;
}
llvm::Function* Config::getLlvmX87DataStorePseudoFunction() const
{
	return _x87DataStoreFunction;
}
bool Config::isLlvmX87DataStorePseudoFunction(llvm::Value* f)
{
	return _x87DataStoreFunction == f;
}
llvm::CallInst* Config::isLlvmX87DataStorePseudoFunctionCall(llvm::Value* c)
{
	auto* cc = dyn_cast_or_null<CallInst>(c);
	return cc && cc->getCalledValue() == _x87DataStoreFunction ? cc : nullptr;
}

void Config::setLlvmX87DataLoadPseudoFunction(llvm::Function* f)
{
	_x87DataLoadFunction = f;
}
llvm::Function* Config::getLlvmX87DataLoadPseudoFunction() const
{
	return _x87DataLoadFunction;
}
bool Config::isLlvmX87DataLoadPseudoFunction(llvm::Value* f)
{
	return _x87DataLoadFunction == f;
}
llvm::CallInst* Config::isLlvmX87DataLoadPseudoFunctionCall(llvm::Value* c)
{
	auto* cc = dyn_cast_or_null<CallInst>(c);
	return cc && cc->getCalledValue() == _x87DataLoadFunction ? cc : nullptr;
}

llvm::CallInst* Config::isLlvmX87StorePseudoFunctionCall(llvm::Value* c)
{
	if (auto* cc = isLlvmX87DataStorePseudoFunctionCall(c)) return cc;
	return nullptr;
}

llvm::CallInst* Config::isLlvmX87LoadPseudoFunctionCall(llvm::Value* c)
{
	if (auto* cc = isLlvmX87DataLoadPseudoFunctionCall(c)) return cc;
	return nullptr;
}

llvm::CallInst* Config::isLlvmAnyBranchPseudoFunctionCall(llvm::Value* c)
{
	if (auto* cc = isLlvmCallPseudoFunctionCall(c)) return cc;
	if (auto* cc = isLlvmReturnPseudoFunctionCall(c)) return cc;
	if (auto* cc = isLlvmBranchPseudoFunctionCall(c)) return cc;
	if (auto* cc = isLlvmCondBranchPseudoFunctionCall(c)) return cc;
	return nullptr;
}

llvm::CallInst* Config::isLlvmAnyUncondBranchPseudoFunctionCall(llvm::Value* c)
{
	if (auto* cc = isLlvmCallPseudoFunctionCall(c)) return cc;
	if (auto* cc = isLlvmReturnPseudoFunctionCall(c)) return cc;
	if (auto* cc = isLlvmBranchPseudoFunctionCall(c)) return cc;
	return nullptr;
}

void Config::addPseudoAsmFunction(llvm::Function* f)
{
	_pseudoAsmFunctions.insert(f);
}

bool Config::isPseudoAsmFunction(llvm::Function* f)
{
	return _pseudoAsmFunctions.count(f);
}

llvm::CallInst* Config::isPseudoAsmFunctionCall(llvm::Value* c)
{
	auto* cc = dyn_cast_or_null<CallInst>(c);
	return isPseudoAsmFunction(cc->getCalledFunction()) ? cc : nullptr;
}

/**
 * Get crypto pattern information for address \p addr - fill \p name,
 * \p description, and \p type, if there is a pattern on address.
 * \return \c True if pattern was found, \c false otherwise.
 */
bool Config::getCryptoPattern(
		retdec::common::Address addr,
		std::string& name,
		std::string& description,
		llvm::Type*& type) const
{
	for (auto& p : getConfig().patterns)
	{
		if (!p.isTypeCrypto())
		{
			continue;
		}

		for (auto& m : p.matches)
		{
			if (m.getAddress() != addr || !m.isSizeDefined())
			{
				continue;
			}

			auto elemCount = m.getSize();
			if (!elemCount.has_value())
			{
				continue;
			}

			Type* elemType = Type::getInt8Ty(_module->getContext());

			if (m.isEntrySizeDefined())
			{
				elemCount = elemCount.value() / m.getEntrySize().value();
				if (m.isTypeFloatingPoint() && m.getEntrySize() == 8)
				{
					elemType = Type::getDoubleTy(_module->getContext());
				}
				else if (m.isTypeFloatingPoint() && m.getEntrySize() == 2)
				{
					elemType = Type::getHalfTy(_module->getContext());
				}
				else if (m.isTypeFloatingPoint() && m.getEntrySize() == 10)
				{
					elemType = Type::getX86_FP80Ty(_module->getContext());
				}
				else if (m.isTypeFloatingPoint())
				{
					elemType = Type::getFloatTy(_module->getContext());
				}
				else // integral || unknown
				{
					elemType = Type::getIntNTy(
							_module->getContext(),
							m.getEntrySize().value() * 8);
				}
			}
			auto d = elemCount.value() > 0 ? elemCount.value() : 1;
			type = ArrayType::get(elemType, d);
			name = retdec::utils::appendHexRet(p.getName() + "_at", addr);
			description = p.getDescription();

			return true;
		}
	}

	return false;
}

void Config::tagFunctionsWithUsedCryptoGlobals()
{
	for (GlobalVariable& lgv : _module->getGlobalList())
	{
		auto* cgv = getConfigGlobalVariable(&lgv);
		if (cgv == nullptr || cgv->getCryptoDescription().empty())
		{
			continue;
		}
		for (auto* user : lgv.users())
		{
			if (auto* i = dyn_cast_or_null<Instruction>(user))
			{
				if (auto* cf = getConfigFunction(i->getFunction()))
				{
					cf->usedCryptoConstants.insert(cgv->getCryptoDescription());
				}
			}
			else if (auto* e = dyn_cast_or_null<ConstantExpr>(user))
			{
				for (auto* u : e->users())
				{
					if (auto* i = dyn_cast_or_null<Instruction>(u))
					{
						if (auto* cf = getConfigFunction(i->getFunction()))
						{
							cf->usedCryptoConstants.insert(cgv->getCryptoDescription());
						}
					}
				}
			}
		}
	}
}

//
//=============================================================================
//  ConfigProvider
//=============================================================================
//

std::map<llvm::Module*, Config> ConfigProvider::_module2config;

Config* ConfigProvider::addConfig(llvm::Module* m, retdec::config::Config& c)
{
	auto p = _module2config.emplace(m, Config::fromConfig(m, c));
	return &p.first->second;
}

Config* ConfigProvider::getConfig(llvm::Module* m)
{
	auto f = _module2config.find(m);
	return f != _module2config.end() ? &f->second : nullptr;
}

bool ConfigProvider::getConfig(llvm::Module* m, Config*& c)
{
	c = getConfig(m);
	return c != nullptr;
}

void ConfigProvider::doFinalization(llvm::Module* m)
{
	auto* c = getConfig(m);
	if (c)
	{
		c->doFinalization();
	}
}

/**
 * Clear all stored data.
 */
void ConfigProvider::clear()
{
	_module2config.clear();
}

} // namespace bin2llvmir
} // namespace retdec
