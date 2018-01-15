/**
 * @file src/bin2llvmir/optimizations/vtable/vtable.cpp
 * @brief Search for vtables in input file.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>
#include <sstream>

#include <llvm/IR/Constants.h>
#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/LLVMContext.h>
#include <llvm/IR/Module.h>
#include <llvm/Support/raw_ostream.h>

#include "retdec/llvm-support/utils.h"
#include "retdec/bin2llvmir/optimizations/vtable/vtable.h"
#include "retdec/bin2llvmir/providers/fileimage.h"
#include "retdec/bin2llvmir/utils/defs.h"
#include "retdec/bin2llvmir/utils/type.h"

using namespace retdec::llvm_support;
using namespace retdec::utils;
using namespace llvm;

#define debug_enabled false

namespace retdec {
namespace bin2llvmir {

//
//=============================================================================
//  VtableAnalysis
//=============================================================================
//

char VtableAnalysis::ID = 0;

static RegisterPass<VtableAnalysis> RegisterPass(
		"vtable-analysis",
		"C++ vtables optimization",
		false, // Only looks at CFG
		false // Analysis Pass
);

VtableAnalysis::VtableAnalysis() :
		ModulePass(ID)
{
}

VtableAnalysis::~VtableAnalysis()
{
	for (auto &p : vtableMap)
	{
		delete p.second;
	}
}

void VtableAnalysis::getAnalysisUsage(AnalysisUsage &AU) const
{
	AU.addRequired<DataReferences>();
	AU.setPreservesAll();
}

bool VtableAnalysis::runOnModule(Module &M)
{
	if (!ConfigProvider::getConfig(&M, config))
	{
		LOG << "[ABORT] config file is not available\n";
		return false;
	}
	if (!FileImageProvider::getFileImage(&M, objf))
	{
		LOG << "[ABORT] object file is not available\n";
		return false;
	}

	module = &M;

	msvc = config->getConfig().tools.isMsvc();
	gcc = !msvc;

	RA = &getAnalysis<DataReferences>();

	detectVtablesInData();

	parseVtables();

	rttiAnalysis.processGccRttis();
	rttiAnalysis.processMsvcRttis();

	createFunctions();
	createVtableStructures();
	setVtablesToConfig();

	return false;
}

void VtableAnalysis::detectVtablesInData()
{
	LOG << "\n*** detectVtablesInData():" << std::endl;

	auto wordSz = objf->getFileFormat()->getBytesPerWord();

	for (auto& seg : objf->getSegments())
	{
		if (seg->getSecSeg() && !seg->getSecSeg()->isSomeData())
		{
			continue;
		}

		auto addr = seg->getAddress();
		auto end = seg->getEndAddress();
		while (addr + wordSz < end)
		{
			std::uint64_t val = 0;
			if (!objf->getImage()->getWord(addr, val))
			{
				addr += wordSz;
				continue;
			}

			if (gcc && val != 0)
			{
				addr += wordSz;
				continue;
			}

			Address item1 = addr + wordSz;
			Address item2 = item1 + wordSz;

			if (!RA->hasReferenceOnAddress(item1)
					|| !RA->hasReferenceOnAddress(item2))
			{
				addr += wordSz;
				continue;
			}

			LOG << "\t" << item2 << " ... OK" << std::endl;
			possibleVtableAddresses.insert(item2);
			addr = item2;
		}
	}
}

void VtableAnalysis::parseVtables()
{
	LOG << "\n*** parseVtables():" << std::endl;

	for (auto addr : possibleVtableAddresses)
	{
		if (vtableMap.find(addr) != vtableMap.end())
		{
			continue;
		}

		if (gcc)
		{
			auto vt = createVtableGcc(addr);
			if (vt)
			{
				LOG << *vt << std::endl;
				vtableMap[addr] = vt;
			}
		}
		else if (msvc)
		{
			auto vt = createVtableMsvc(addr);
			if (vt)
			{
				LOG << *vt << std::endl;
				vtableMap[addr] = vt;
			}
		}
	}
}

VtableGcc *VtableAnalysis::createVtableGcc(Address a)
{
	LOG << "\n*** createVtableGcc() @ " << a << std::endl;

	VtableGcc *ret = new VtableGcc(a);

	if (!fillVtable(a, static_cast<Vtable&>(*ret)))
	{
		delete ret;
		return nullptr;
	}

	a -= objf->getFileFormat()->getBytesPerWord();
	std::uint64_t tmp = 0;
	if (objf->getImage()->getWord(a, tmp))
	{
		ret->rttiAddress = tmp;

		ret->rtti = rttiAnalysis.parseGccRtti(objf->getImage(), RA, ret->rttiAddress);
		if (ret->rtti == nullptr)
		{
			LOG << "[FAILED] parsing rtti @ " << ret->rttiAddress
				<<  std::endl << std::endl;
			delete ret;
			return nullptr;
		}
	}
	else
	{
		delete ret;
		return nullptr;
	}

	if (ret->virtualFncAddresses.size())
	{
		return ret;
	}
	else
	{
		delete ret;
		return nullptr;
	}
}

VtableMsvc *VtableAnalysis::createVtableMsvc(Address a)
{
	LOG << "\n*** createVtableMsvc() @ " << a << std::endl;

	VtableMsvc *ret = new VtableMsvc(a);

	if (!fillVtable(a, static_cast<Vtable&>(*ret)))
	{
		LOG << "[FAILED] filling vtable @ " << a << std::endl << std::endl;
		delete ret;
		return nullptr;
	}

	a -= objf->getFileFormat()->getBytesPerWord();
	std::uint64_t tmp = 0;
	if (objf->getImage()->getWord(a, tmp))
	{
		ret->objLocatorAddress = tmp;

		ret->rtti = rttiAnalysis.parseMsvcObjectLocator(
				objf->getImage(),
				ret->objLocatorAddress);
		if (ret->rtti == nullptr)
		{
			LOG << "[FAILED] parsing object locator @ "
				<< ret->objLocatorAddress << std::endl << std::endl;
			delete ret;
			return nullptr;
		}
	}
	else
	{
		delete ret;
		return nullptr;
	}

	if (ret->virtualFncAddresses.size())
	{
		return ret;
	}
	else
	{
		delete ret;
		return nullptr;
	}
}

/**
 * @return @c True if vtable ok and can be used, @c false if it should
 * be thrown away.
 */
bool VtableAnalysis::fillVtable(Address a, Vtable &vt)
{
	LOG << "\n*** fillVtable() @ " << a << std::endl;

	auto ref = RA->getReferenceFromAddress(a);
	AddressSet items;

	// TODO: maybe we should check that it is not in possibleVtableAddresses
	// (except first item). According to some papers, only first item is
	// referenced from code. Without checking it, we might merge two tables
	// together. But if we check it, and some other item will be referenced,
	// then we split one table into two.
	//
	while (true)
	{
		if (!ref)
		{
			LOG << "\tnot ref @ " << a << std::endl;
			break;
		}
		if (processedAddresses.find(a) != processedAddresses.end())
		{
			LOG << "\talready processed @ " << a << std::endl;
			break;
		}
		if (ref->seg == nullptr)
		{
			LOG << "\tno associated segment @ " << a << std::endl;
			break;
		}
		if (ref->seg->getSecSeg() && !ref->seg->getSecSeg()->isSomeCode())
		{
			LOG << "\tnot ref to code @ " << a << std::endl;
			break;
		}

		// All items in vtable must be unique.
		// TODO: does this really hold?
		//
		if (items.find(ref->addr) != items.end())
		{
			LOG << "[FAILED] items are not unique @ " << a
				<< std::endl << std::endl;
			return false;
		}

		auto* f = config->getLlvmFunction(ref->addr);

		LOG << "\t[OK] item @ " << a << std::endl;
		vt.virtualFncAddresses.push_back( VtableItem(ref->addr, f));
		items.insert(ref->addr);
		processedAddresses.insert(a);

		a += objf->getFileFormat()->getBytesPerWord();
		ref = RA->getReferenceFromAddress(a);
	}

	if (vt.virtualFncAddresses.empty())
	{
		LOG << "[FAILED] items are empty @ " << a << std::endl << std::endl;
		return false;
	}
	else
	{
		return true;
	}
}

const VtableAnalysis::VtableMap& VtableAnalysis::getVtableMap() const
{
	return vtableMap;
}

/**
 * @return Vtable on address @p a or nullptr if not found.
 */
Vtable* VtableAnalysis::getVtableOnAddress(retdec::utils::Address a) const
{
	auto fIt = vtableMap.find(a);
	return (fIt != vtableMap.end()) ? (fIt->second) : (nullptr);
}

/**
 * TODO: There might be vtable entries, which do not have function associated
 * with them. This method should create new functions on items' target
 * addresses. However, we are currently unable to do so in bin2llvmirl, since we
 * do not known which instructions are on which addresses.
 * Therefore, we just create dummy declarations instead.
 */
void VtableAnalysis::createFunctions()
{
	for (auto& p : vtableMap)
	{
		auto& vt = p.second;
		for (auto& item : vt->virtualFncAddresses)
		{
			if (item.function == nullptr)
			{
				std::stringstream ss;
				ss << std::hex << item.address;
				std::string name = "function_" + ss.str();

				auto* ft = FunctionType::get(
						Type::getInt32Ty(module->getContext()),
						false);
				item.function = Function::Create(
						ft,
						GlobalValue::ExternalLinkage,
						name,
						module);
			}
		}
	}
}

void VtableAnalysis::createVtableStructures()
{
	for (auto& p : vtableMap)
	{
		auto& vt = p.second;

		std::string varName = vt->getName();
		std::string typeName = varName + "_type";

		std::vector<Type*> itemTypes;
		std::vector<Constant*> functionPtrs;
		for (auto& item : vt->virtualFncAddresses)
		{
			assert(item.function);
			itemTypes.push_back(item.function->getType());
			functionPtrs.push_back(item.function);
		}

		StructType *structType = StructType::create(itemTypes, typeName);
		Constant *init = ConstantStruct::get(structType, functionPtrs);

		auto* configOld = config->getLlvmGlobalVariable(vt->vtableAddress);
		if (configOld)
		{
			vt->global = dyn_cast<GlobalVariable>(changeObjectType(
					config,
					objf,
					module,
					configOld,
					structType,
					init));
			continue;
		}

		auto* existingLlvm = module->getGlobalVariable(varName);
		if (existingLlvm)
		{
			vt->global = existingLlvm;
			continue;
		}

		auto* tmp = module->getOrInsertGlobal(varName, structType);
		GlobalVariable* global = dyn_cast_or_null<GlobalVariable>(tmp);
		assert(global != nullptr);
		global->setInitializer(init);

		vt->global = global;
	}
}

void VtableAnalysis::setVtablesToConfig()
{
	for (auto& p : vtableMap)
	{
		auto& vt = p.second;

		retdec::config::Vtable confVt(vt->vtableAddress);
		confVt.setName(vt->getName());

		retdec::utils::Address itemAddr = vt->vtableAddress;
		for (auto& item : vt->virtualFncAddresses)
		{
			retdec::config::VtableItem confItem(itemAddr);
			confItem.setTargetFunctionAddress(item.address);
			if (item.function)
				confItem.setTargetFunctionName(item.function->getName().str());
			confVt.items.insert(confItem);

			itemAddr += config->getConfig().architecture.getByteSize();
		}

		config->getConfig().vtables.insert(confVt);

		retdec::config::Object cg(
				vt->global->getName(),
				retdec::config::Storage::inMemory(vt->vtableAddress)
		);
		cg.setIsFromDebug(true);
		config->getConfig().globals.insert(cg);
	}
}

//
//=============================================================================
//  Vtable
//=============================================================================
//

Vtable::Vtable(Address a) :
		vtableAddress(a)
{

}

std::string Vtable::getName() const
{
	std::stringstream ss;
	ss << std::hex << vtableAddress;
	return "vtable_" + ss.str();
}

std::ostream& operator<<(std::ostream &out, const Vtable &v)
{
	out << "--> " << v.vtableAddress << std::endl;
	unsigned cntr = 0;
	for (const auto &i : v.virtualFncAddresses)
	{
		out << "    fnc " << (cntr++) << " = " << i.address;
		if (i.function)
			out << " (" << i.function->getName().str() << ")";
		out << std::endl;
	}
	return out;
}

//
//=============================================================================
//  VtableGcc
//=============================================================================
//

VtableGcc::VtableGcc(Address a) :
		Vtable(a),
		topOffset(0)
{

}

std::ostream& operator<<(std::ostream &out, const VtableGcc &v)
{
	out << "VtableGcc:" << std::endl;
	out << "    rttiAddress = " << v.rttiAddress << std::endl;
	out << static_cast<const Vtable&>(v);

	return out;
}

//
//=============================================================================
//  VtableMsvc
//=============================================================================
//

VtableMsvc::VtableMsvc(Address a) :
		Vtable(a)
{

}

std::ostream& operator<<(std::ostream &out, const VtableMsvc &v)
{
	out << "VtableMsvc:" << std::endl;
	out << "    objLocatorAddress = " << v.objLocatorAddress << std::endl;
	out << static_cast<const Vtable&>(v);

	return out;
}

//
//=============================================================================
//  VtableMsvc
//=============================================================================
//

VtableItem::VtableItem(retdec::utils::Address a, llvm::Function* f) :
		address(a),
		function(f)
{

}

} // namespace bin2llvmir
} // namespace retdec
