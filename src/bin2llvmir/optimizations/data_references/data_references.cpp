/**
 * @file src/bin2llvmir/optimizations/data_references/data_references.cpp
 * @brief Search for references in input file.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>

#include <llvm/IR/Instruction.h>
#include <llvm/IR/Instructions.h>
#include <llvm/IR/Module.h>

#include "retdec/llvm-support/utils.h"
#include "retdec/bin2llvmir/optimizations/data_references/data_references.h"
#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/utils/defs.h"

using namespace retdec::llvm_support;
using namespace retdec::utils;
using namespace llvm;
using namespace retdec::loader;

#define debug_enabled false

namespace retdec {
namespace bin2llvmir {

//
//=============================================================================
//  DataReferences
//=============================================================================
//

char DataReferences::ID = 0;

static RegisterPass<DataReferences> RegisterPass(
		"reference-analysis",
		"Input file references optimization",
		false,
		false
);

DataReferences::DataReferences() :
		llvm::ModulePass(ID)
{
}

void DataReferences::getAnalysisUsage(AnalysisUsage &AU) const
{
	AU.setPreservesAll();
}

bool DataReferences::runOnModule(Module &M)
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

	detectReferencesIntoSegments();
	linkReferencesWithKnownObjects();

	return false;
}

void DataReferences::detectReferencesIntoSegments()
{
	LOG << "\n*** detectReferencesIntoSegments():" << std::endl;

	const auto& conf = config->getConfig();
	for (const auto& seg : objf->getSegments())
	{
		for (Address a = seg->getAddress();
				a < seg->getEndAddress();
				a += objf->getFileFormat()->getBytesPerWord())
		{
			std::uint64_t tmp = 0;
			if (!objf->getImage()->getWord(a, tmp))
				continue;

			Address val = tmp;
			if (conf.architecture.isArmOrThumb() && val % 2)
			{
				--val;
			}

			const Segment* ref = objf->getImage()->getSegmentFromAddress(val);
			if (ref)
			{
				ReferencedObject r(val);
				r.seg = ref;
				addr2obj.insert( {a, r} );

				LOG << a << " @ " << seg->getName() << " -> "
				    << val << " @ " << ref->getName() << "\n";
			}
		}
	}
}

void DataReferences::linkReferencesWithKnownObjects()
{
	LOG << "\n*** linkReferencesWithKnownObjects():" << std::endl;

	for (auto &ref : addr2obj)
	{
		Address a = ref.second.addr;

		ref.second.function = config->getLlvmFunction(a);
		ref.second.globalVar = config->getLlvmGlobalVariable(a);
		ref.second.instruction = nullptr; // TODO: associate address and instruction.

		if (ref.second.function)
		{
			LOG << a << " == " << ref.second.function->getName().str()
				<< std::endl;
		}
		if (ref.second.globalVar)
		{
			LOG << a << " == " << ref.second.globalVar->getName().str()
				<< std::endl;
		}
		if (ref.second.instruction)
		{
			LOG << a << " == " << ref.second.instruction->getName().str()
				<< std::endl;
		}
	}
}

const DataReferences::Addr2Obj& DataReferences::getAddressToObjectMapping() const
{
	return addr2obj;
}

bool DataReferences::hasReferenceOnAddress(Address a) const
{
	auto fIt = addr2obj.find(a);
	return fIt != addr2obj.end();
}

const DataReferences::ReferencedObject* DataReferences::getReferenceFromAddress(Address a) const
{
	auto fIt = addr2obj.find(a);
	return (fIt != addr2obj.end()) ? (&fIt->second) : (nullptr);
}

//
//=============================================================================
//  DataReferences::ReferencedObject
//=============================================================================
//

DataReferences::ReferencedObject::ReferencedObject(Address a) :
		addr(a)
{
}

} // namespace bin2llvmir
} // namespace retdec
