/**
 * @file src/bin2llvmir/utils/global_var.cpp
 * @brief LLVM global variable utilities.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/llvm-support/utils.h"
#include "retdec/utils/string.h"
#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/utils/global_var.h"
#include "retdec/bin2llvmir/utils/type.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

namespace {

/**
 * Check if we can initialize the given global variable @c gv at address @c addr
 * with initializer @c c read from object file @c objf -- initialization will
 * not create init cycle.
 * @return Original constant @c c if cycle is not detected, integer value if
 * cycle is detected, @c nullptr if integer value can not be read.
 */
Constant* detectGlobalVariableInitializerCycle(
		Module* module,
		GlobalVariable* gv,
		Constant* c,
		FileImage* objf,
		retdec::utils::Address addr)
{
	if (gv == nullptr || c == nullptr || objf == nullptr || addr.isUndefined())
	{
		return nullptr;
	}
	if (c == gv)
	{
		return objf->getConstant(getDefaultType(module), addr);
	}

	auto* cgv = dyn_cast<GlobalVariable>(c);
	while (cgv)
	{
		if (cgv == gv)
		{
			c = objf->getConstant(getDefaultType(module), addr);
			break;
		}
		if (cgv->hasInitializer())
		{
			cgv = dyn_cast<GlobalVariable>(cgv->getInitializer());
		}
		else
		{
			cgv = nullptr;
		}
	}

	return c;
}

bool globalVariableCanBeCreated(
		Module* module,
		Config* config,
		FileImage* objf,
		retdec::utils::Address &addr,
		bool strict = false)
{
	if (module == nullptr || objf == nullptr || addr.isUndefined())
	{
		return false;
	}
	if (!objf->getImage()->hasDataOnAddress(addr))
	{
		return false;
	}
	auto* seg = objf->getImage()->getSegmentFromAddress(addr);

	// TODO: how to protect agains very small, but "valid" memory, numbers.
	// sometimes, data are mapped to very low addresses.
	//
	if (addr < 0x4000)
	{
		if (seg && seg->getSecSeg()->isSomeData() && seg->containsAddress(addr))
		{
			// ok
		}
		else
		{
			return false;
		}
	}

	// TODO: it would be greate to use this info here, but vtable analysis
	// can not handle it at the moment -> some features.cpp tests fail.
	//
	std::string str;
	auto* fnc = config->getLlvmFunction(addr);
	if (fnc || (seg && seg->getSecSeg() && seg->getSecSeg()->isCode()))
	{
		if (!(objf->getImage()->getNTBS(addr, str) && retdec::utils::isNiceString(str, 1.0)))
		{
			uint64_t val = 0;
			if (objf->getImage()->getWord(addr, val))
			{
				if (objf->getImage()->hasDataOnAddress(val))
				{
					return true;
				}
			}
			if (objf->getImage()->getWord(addr+getDefaultTypeByteSize(module), val))
			{
				if (objf->getImage()->hasDataOnAddress(val))
				{
					return true;
				}
			}
			if (objf->getImage()->getWord(addr-getDefaultTypeByteSize(module), val))
			{
				if (objf->getImage()->hasDataOnAddress(val))
				{
					return true;
				}
			}

			// ARM has data after functions, Pic32 does not bother to mark data (e.g. rodata) as data.
			if ((config->getConfig().architecture.isArmOrThumb() || config->isPic32()) && !strict)
			{
				return true;
			}

			return false;
		}
	}

	return true;
}

} // anonymous namespace

/**
 * TODO: This should be private to this module -- impossible to call from
 * other modules. Once all globals are detected in bin2llvmirl, make this
 * private.
 */
bool getGlobalInfoFromCryptoPatterns(
		Module* module,
		Config* config,
		retdec::utils::Address addr,
		std::string& name,
		std::string& description,
		Type*& type)
{
	for (auto& p : config->getConfig().patterns)
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

			unsigned elemCount = m.getSize();
			Type* elemType = Type::getInt8Ty(module->getContext());

			if (m.isEntrySizeDefined())
			{
				elemCount /= m.getEntrySize();
				if (m.isTypeFloatingPoint() && m.getEntrySize() == 8)
				{
					elemType = Type::getDoubleTy(module->getContext());
				}
				else if (m.isTypeFloatingPoint() && m.getEntrySize() == 2)
				{
					elemType = Type::getHalfTy(module->getContext());
				}
				else if (m.isTypeFloatingPoint() && m.getEntrySize() == 10)
				{
					elemType = Type::getX86_FP80Ty(module->getContext());
				}
				else if (m.isTypeFloatingPoint())
				{
					elemType = Type::getFloatTy(module->getContext());
				}
				else // integral || unknown
				{
					elemType = Type::getIntNTy(module->getContext(), m.getEntrySize() * 8);
				}
			}
			auto d = elemCount > 0 ? elemCount : 1;
			type = ArrayType::get(elemType, d);
			name = retdec::utils::appendHexRet(p.getName() + "_at", addr);
			description = p.getDescription();

			return true;
		}
	}

	return false;
}

/**
 * Get global variable from the given address @a addr in @a objf input file.
 * @param module Module in which global variable is created.
 * @param config Config file.
 * @param objf Object file.
 * @param dbgf Debug file.
 * @param addr Address of the global variable in the @a objf.
 * @param strict Be stricter when determining if variable can be created.
 * @param name Name to use. Global's address is always appended to this name.
 * @return Global variable on the given address, or @c nullptr.
 *
 * TODO: there is many more things to do here:
 * - create second similar method taking global variable type, or add default
 *   parameter to this method. if type specified, it is forced.
 * - check that such global variable does not already exist, config is needed,
 *   if so, do not create new, use the old one
 * - check debug info for variable on the specified address, if it exists,
 *   use name, type, ...
 * - add/update info about this variable into config
 */
GlobalVariable* getGlobalVariable(
		Module* module,
		Config* config,
		FileImage* objf,
		DebugFormat* dbgf,
		retdec::utils::Address addr,
		bool strict,
		std::string name)
{
	if (!globalVariableCanBeCreated(module, config, objf, addr, strict))
	{
		return nullptr;
	}

	retdec::utils::appendHex(name, addr);

	if (auto* gv = config->getLlvmGlobalVariable(name, addr))
	{
		return gv;
	}

	Constant* c = nullptr;
	Type* t = getDefaultType(module);
	bool isConstant = objf->getImage()->hasReadOnlyDataOnAddress(addr);
	bool isFromDebug = false;
	std::string realName;

	auto* dgv = dbgf ? dbgf->getGlobalVar(addr) : nullptr;
	if (dgv)
	{
		auto* dt = stringToLlvmType(module->getContext(), dgv->type.getLlvmIr());
		t = dt ? dt : t;
		c = objf->getConstant(t, addr);
		name = dgv->getName();
		realName = dgv->getName();
		isFromDebug = true;
	}

	auto* cgv = config->getConfigGlobalVariable(addr);
	if (cgv)
	{
		auto* dt = stringToLlvmType(module->getContext(), cgv->type.getLlvmIr());
		t = dt ? dt : t;
		c = objf->getConstant(t, addr);
		name = cgv->getName();
		realName = cgv->getName();
		isFromDebug = true;
	}

	std::string cryptoName;
	std::string cryptoDesc;
	Type* cryptoType = nullptr;
	if (getGlobalInfoFromCryptoPatterns(
			module,
			config,
			addr,
			cryptoName,
			cryptoDesc,
			cryptoType))
	{
		if (!isFromDebug)
		{
			t = cryptoType;
			c = objf->getConstant(t, addr);
			name = cryptoName;
			realName = cryptoName;
			isFromDebug = true;
		}
	}

	auto* gv = new GlobalVariable(
			*module,
			t,
			isConstant,
			GlobalValue::ExternalLinkage,
			c,
			name);

	if (c == nullptr)
	{
		c = objf->getConstant(config, dbgf, addr);
		c = detectGlobalVariableInitializerCycle(module, gv, c, objf, addr);
		if (c == nullptr)
		{
			config->insertGlobalVariable(
					gv,
					addr,
					isFromDebug,
					realName,
					cryptoDesc);
			return nullptr;
		}

		auto* ngv = new GlobalVariable(
				*module,
				c->getType(),
				isConstant,
				GlobalValue::ExternalLinkage,
				c,
				name);

		auto* conv = convertConstantToType(ngv, gv->getType());
		if (conv != ngv)
		{
			gv->replaceAllUsesWith(conv);
		}
		gv->eraseFromParent();
		gv = ngv;
	}

	config->insertGlobalVariable(
			gv,
			addr,
			isFromDebug,
			realName,
			cryptoDesc);

	return gv;
}

} // namespace bin2llvmir
} // namespace retdec
