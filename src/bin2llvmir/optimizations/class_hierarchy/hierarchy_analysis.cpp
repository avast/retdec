/**
 * @file src/bin2llvmir/optimizations/class_hierarchy/hierarchy_analysis.cpp
 * @brief Analyse results of other analyses to reconstruct class hierarchy.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>

#include "retdec/llvm-support/utils.h"
#include "retdec/bin2llvmir/optimizations/class_hierarchy/hierarchy_analysis.h"
#include "retdec/bin2llvmir/utils/defs.h"

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

void ClassHierarchyAnalysis::getAnalysisUsage(AnalysisUsage& AU) const
{
	AU.addRequired<VtableAnalysis>();
	AU.addRequired<CtorDtor>();
	AU.setPreservesAll();
}

bool ClassHierarchyAnalysis::runOnModule(Module& M)
{
	if (!ConfigProvider::getConfig(&M, config))
	{
		LOG << "[ABORT] config file is not available\n";
		return false;
	}

	processRttiGcc();
	processRttiMsvc();
	processCtorsDtors();
	setToConfig(&M);

	LOG << classHierarchy.dump();

	return false;
}

void ClassHierarchyAnalysis::processRttiGcc()
{
	auto& rttiGcc = getAnalysis<VtableAnalysis>().rttiAnalysis.gccRttis;

	Class* c = nullptr;
	std::map<ClassTypeInfo*, Class*> rtti2class;

	for (auto& rtti : rttiGcc)
	{
		c = classHierarchy.addAndGetNewClass();
		c->name = rtti.second->name;
		c->gccRtti = rtti.second;
		rtti2class[c->gccRtti] = c;
	}

	for (auto& rtti : rttiGcc)
	{
		auto fIt = rtti2class.find(rtti.second);
		assert(fIt != rtti2class.end());
		c = fIt->second;

		if (auto* scti = dynamic_cast<SiClassTypeInfo*>(rtti.second))
		{
			auto fIt = rtti2class.find(scti->baseClass);
			assert(fIt != rtti2class.end());
			c->superClasses.insert(fIt->second);
		}
		else if (auto* vcti = dynamic_cast<VmiClassTypeInfo*>(rtti.second))
		{
			for (auto& bi : vcti->baseInfo)
			{
				auto fIt = rtti2class.find(bi.baseClass);
				assert(fIt != rtti2class.end());
				c->superClasses.insert(fIt->second);
			}
		}
	}

	processVtablesGcc(rtti2class);
}

void ClassHierarchyAnalysis::processRttiMsvc()
{
	auto& rttiA = getAnalysis<VtableAnalysis>().rttiAnalysis;

	Class* c = nullptr;
	std::map<RTTITypeDescriptor*, Class*> rtti2class;

	for (auto& rtti : rttiA.msvcTypeDescriptors)
	{
		c = classHierarchy.addAndGetNewClass();
		c->name = rtti.second.name;
		c->msvcRtti = &rtti.second;
		rtti2class[c->msvcRtti] = c;
	}

	for (auto& objLoc : rttiA.msvcObjLocators)
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
		std::map<ClassTypeInfo*, Class*> &rtti2class)
{
	auto& vtables = getAnalysis<VtableAnalysis>().getVtableMap();
	auto& cdtor = getAnalysis<CtorDtor>().getResults();

	for (auto& vt : vtables)
	{
		VtableGcc* gcc = dynamic_cast<VtableGcc*>(vt.second);
		if (gcc == nullptr)
			continue;

		auto fIt = rtti2class.find(gcc->rtti);
		assert(fIt != rtti2class.end());
		auto* c = fIt->second;

		for (auto& vf : gcc->virtualFncAddresses)
		{
			c->virtualFunctions.insert(vf.function);

			auto cIt = cdtor.find(vf.function);
			if (cIt == cdtor.end())
				continue;

			if (cIt->second.ctor)
				c->constructors.insert(vf.function);
			if (cIt->second.dtor)
				c->destructors.insert(vf.function);
		}

		c->virtualFunctionTables.insert(gcc);
	}
}

void ClassHierarchyAnalysis::processVtablesMsvc(
		std::map<RTTITypeDescriptor*, Class*> &rtti2class)
{
	auto& vtables = getAnalysis<VtableAnalysis>().getVtableMap();
	auto& cdtor = getAnalysis<CtorDtor>().getResults();

	for (auto& vt : vtables)
	{
		VtableMsvc* msvc = dynamic_cast<VtableMsvc*>(vt.second);
		if (msvc == nullptr)
			continue;

		auto fIt = rtti2class.find(msvc->rtti->typeDescriptor);
		assert(fIt != rtti2class.end());
		auto* c = fIt->second;

		for (auto& vf : msvc->virtualFncAddresses)
		{
			c->virtualFunctions.insert(vf.function);

			auto cIt = cdtor.find(vf.function);
			if (cIt == cdtor.end())
				continue;

			if (cIt->second.ctor)
				c->constructors.insert(vf.function);
			if (cIt->second.dtor)
				c->destructors.insert(vf.function);
		}

		c->virtualFunctionTables.insert(msvc);
	}
}

void ClassHierarchyAnalysis::processCtorsDtors()
{
	LOG << "\n*** processCtorsDtors()" << std::endl;

	auto& cdtor = getAnalysis<CtorDtor>().getResults();
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
