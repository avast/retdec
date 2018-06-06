/**
 * @file src/bin2llvmir/optimizations/class_hierarchy/hierarchy_analysis.cpp
 * @brief Analyse results of other analyses to reconstruct class hierarchy.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>

#include "retdec/bin2llvmir/utils/llvm.h"
#include "retdec/bin2llvmir/optimizations/class_hierarchy/hierarchy_analysis.h"
#include "retdec/bin2llvmir/utils/debug.h"
#include "retdec/bin2llvmir/utils/ir_modifier.h"

#define debug_enabled false

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

char ClassHierarchyAnalysis::ID = 0;

static RegisterPass<ClassHierarchyAnalysis> RegisterPass(
		"class-hierarchy",
		"C++ class hierarchy optimization",
		false, // Only looks at CFG
		false // Analysis Pass
);

ClassHierarchyAnalysis::ClassHierarchyAnalysis() :
		ModulePass(ID)
{

}

bool ClassHierarchyAnalysis::runOnModule(Module& M)
{
	if (!ConfigProvider::getConfig(&M, config))
	{
		LOG << "[ABORT] config file is not available\n";
		return false;
	}
	if (!FileImageProvider::getFileImage(&M, image))
	{
		LOG << "[ABORT] config file is not available\n";
		return false;
	}

	ctorDtor.runOnModule(&M, config, image);

//=============================================================================

IrModifier irModif(&M, config);

std::vector<const rtti_finder::Vtable*> vtable;

for (auto& p : image->getRtti().getVtablesGcc())
{
	vtable.push_back(&p.second);
}
for (auto& p : image->getRtti().getVtablesMsvc())
{
	vtable.push_back(&p.second);
}

for (auto* p : vtable)
{
	auto& vt = *p;
	for (auto& item : vt.virtualFncAddresses)
	{
		auto *fnc = config->getLlvmFunction(item.address);
		if (fnc == nullptr)
		{
			std::string name = names::generateFunctionName(item.address);

			auto* ft = FunctionType::get(
					Type::getInt32Ty(M.getContext()),
					false);
			fnc = Function::Create(
					ft,
					GlobalValue::ExternalLinkage,
					name,
					&M);

			config->insertFunction(fnc, item.address);
		}
	}
}

//=============================================================================

for (auto* p : vtable)
{
	auto& vt = *p;

	std::string varName = names::generateVtableName(vt.vtableAddress);
	std::string typeName = varName + "_type";

	std::vector<Type*> itemTypes;
	std::vector<Constant*> functionPtrs;
	for (auto& item : vt.virtualFncAddresses)
	{
		auto *fnc = config->getLlvmFunction(item.address);
		assert(fnc);
		itemTypes.push_back(fnc->getType());
		functionPtrs.push_back(fnc);
	}

	StructType *structType = StructType::create(itemTypes, typeName);
	Constant *init = ConstantStruct::get(structType, functionPtrs);

	auto* configOld = config->getLlvmGlobalVariable(vt.vtableAddress);
	if (configOld)
	{
		irModif.changeObjectType(
				image,
				configOld,
				structType,
				init);
		continue;
	}

	auto* existingLlvm = M.getGlobalVariable(varName);
	if (existingLlvm)
	{
		config->insertGlobalVariable(existingLlvm, vt.vtableAddress);
		continue;
	}

	auto* tmp = M.getOrInsertGlobal(varName, structType);
	GlobalVariable* global = dyn_cast_or_null<GlobalVariable>(tmp);
	assert(global != nullptr);
	global->setInitializer(init);

	config->insertGlobalVariable(global, vt.vtableAddress);
}

//=============================================================================

for (auto* p : vtable)
{
	auto& vt = *p;

	retdec::config::Vtable confVt(vt.vtableAddress);
	confVt.setName(names::generateVtableName(vt.vtableAddress));

	retdec::utils::Address itemAddr = vt.vtableAddress;
	for (auto& item : vt.virtualFncAddresses)
	{
		retdec::config::VtableItem confItem(itemAddr);
		confItem.setTargetFunctionAddress(item.address);
		if (auto *fnc = config->getLlvmFunction(item.address))
			confItem.setTargetFunctionName(fnc->getName().str());
		confVt.items.insert(confItem);

		itemAddr += config->getConfig().architecture.getByteSize();
	}

	config->getConfig().vtables.insert(confVt);

	auto* global = config->getLlvmGlobalVariable(vt.vtableAddress);
	assert(global);

	retdec::config::Object cg(
			global->getName(),
			retdec::config::Storage::inMemory(vt.vtableAddress)
	);
	cg.setIsFromDebug(true);
	config->getConfig().globals.insert(cg);
}

//=============================================================================

	processRttiGcc();
	processRttiMsvc();
	processCtorsDtors();
	setToConfig(&M);

	LOG << classHierarchy.dump();

	return false;
}

void ClassHierarchyAnalysis::processRttiGcc()
{
	auto& rttiGcc = image->getRtti().getRttiGcc();

	Class* c = nullptr;
	std::map<const rtti_finder::ClassTypeInfo*, Class*> rtti2class;

	for (auto& rtti : rttiGcc)
	{
		c = classHierarchy.addAndGetNewClass();
		c->name = rtti.second->name;
		c->gccRtti = rtti.second.get();
		rtti2class[c->gccRtti] = c;
	}

	for (auto& rtti : rttiGcc)
	{
		auto fIt = rtti2class.find(rtti.second.get());
		assert(fIt != rtti2class.end());
		c = fIt->second;

		if (auto* scti = dynamic_cast<rtti_finder::SiClassTypeInfo*>(rtti.second.get()))
		{
			auto fIt = rtti2class.find(scti->baseClass.get());
			assert(fIt != rtti2class.end());
			c->superClasses.insert(fIt->second);
		}
		else if (auto* vcti = dynamic_cast<rtti_finder::VmiClassTypeInfo*>(rtti.second.get()))
		{
			for (auto& bi : vcti->baseInfo)
			{
				auto fIt = rtti2class.find(bi.baseClass.get());
				assert(fIt != rtti2class.end());
				c->superClasses.insert(fIt->second);
			}
		}
	}

	processVtablesGcc(rtti2class);
}

void ClassHierarchyAnalysis::processRttiMsvc()
{
	auto& rttiA = image->getRtti().getRttiMsvc();

	Class* c = nullptr;
	std::map<const rtti_finder::RTTITypeDescriptor*, Class*> rtti2class;

	for (auto& rtti : rttiA.typeDescriptors)
	{
		c = classHierarchy.addAndGetNewClass();
		c->name = rtti.second.name;
		c->msvcRtti = &rtti.second;
		rtti2class[c->msvcRtti] = c;
	}

	for (auto& objLoc : rttiA.objLocators)
	{
		auto fIt = rtti2class.find(objLoc.second.typeDescriptor);
		assert(fIt != rtti2class.end());
		c = fIt->second;

		for (auto* bc : objLoc.second.classDescriptor->baseClasses)
		{
			// In MSVC, class is its own base.
			if (bc->typeDescriptor == objLoc.second.typeDescriptor)
				continue;

			fIt = rtti2class.find(bc->typeDescriptor);
			assert(fIt != rtti2class.end());
			c->superClasses.insert(fIt->second);
		}
	}

	processVtablesMsvc(rtti2class);
}

void ClassHierarchyAnalysis::processVtablesGcc(
		std::map<const rtti_finder::ClassTypeInfo*, Class*> &rtti2class)
{
	auto& vtables = image->getRtti().getVtablesGcc();
	auto& cdtor = ctorDtor.getResults();

	for (auto& vt : vtables)
	{
		const rtti_finder::VtableGcc* gcc = &vt.second;
		auto fIt = rtti2class.find(gcc->rtti.get());
		assert(fIt != rtti2class.end());
		auto* c = fIt->second;

		for (auto& vf : gcc->virtualFncAddresses)
		{
			auto* fnc = config->getLlvmFunction(vf.address);
			assert(fnc);
			c->virtualFunctions.insert(fnc);

			auto cIt = cdtor.find(fnc);
			if (cIt == cdtor.end())
				continue;

			if (cIt->second.ctor)
				c->constructors.insert(fnc);
			if (cIt->second.dtor)
				c->destructors.insert(fnc);
		}

		c->virtualFunctionTables.insert(gcc);
	}
}

void ClassHierarchyAnalysis::processVtablesMsvc(
		std::map<const rtti_finder::RTTITypeDescriptor*, Class*> &rtti2class)
{
	auto& vtables = image->getRtti().getVtablesMsvc();
	auto& cdtor = ctorDtor.getResults();

	for (auto& vt : vtables)
	{
		const rtti_finder::VtableMsvc* msvc = &vt.second;
		auto fIt = rtti2class.find(msvc->rtti->typeDescriptor);
		assert(fIt != rtti2class.end());
		auto* c = fIt->second;

		for (auto& vf : msvc->virtualFncAddresses)
		{
			auto* fnc = config->getLlvmFunction(vf.address);
			assert(fnc);
			c->virtualFunctions.insert(fnc);

			auto cIt = cdtor.find(fnc);
			if (cIt == cdtor.end())
				continue;

			if (cIt->second.ctor)
				c->constructors.insert(fnc);
			if (cIt->second.dtor)
				c->destructors.insert(fnc);
		}

		c->virtualFunctionTables.insert(msvc);
	}
}

void ClassHierarchyAnalysis::processCtorsDtors()
{
	LOG << "\n*** processCtorsDtors()" << std::endl;

	auto& cdtor = ctorDtor.getResults();
	for (auto& p : cdtor)
	{
		LOG << "\t" << p.first->getName().str() << std::endl;

		if (p.second.vftableStores.empty())
		{
			LOG << "\t\tcontinue" << std::endl;
			continue;
		}

		auto* lastVtableStored = p.second.vftableStores.back().second;

		for (auto& c : classHierarchy.classes)
		{
			for (auto* vt : c.virtualFunctionTables)
			{
				if (vt == lastVtableStored)
				{
					if (p.second.ctor)
					{
						c.constructors.insert(p.first);
					}
					if (p.second.dtor)
					{
						c.destructors.insert(p.first);
					}
				}
			}
		}
	}
}

void ClassHierarchyAnalysis::setToConfig(llvm::Module* m) const
{
	for (auto& c : classHierarchy.classes)
	{
		config->getConfig().classes.insert(c.getConfigClass(m, config));
	}
}

} // namespace bin2llvmir
} // namespace retdec
