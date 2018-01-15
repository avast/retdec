/**
 * @file src/bin2llvmir/optimizations/vtable/rtti_analysis.cpp
 * @brief Search for RTTI in input file.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>

#include "retdec/utils/string.h"
#include "retdec/bin2llvmir/optimizations/vtable/rtti_analysis.h"
#include "retdec/bin2llvmir/utils/defs.h"

using namespace retdec::utils;
using namespace llvm;

#define debug_enabled false

namespace retdec {
namespace bin2llvmir {

RttiAnalysis::~RttiAnalysis()
{
	for (auto &p : gccRttis)
	{
		delete p.second;
	}
}

ClassTypeInfo* RttiAnalysis::parseGccRtti(
		retdec::loader::Image* objfile,
		DataReferences* RA,
		Address rttiAddr)
{
	objf = objfile;
	assert(objf);

	LOG << "\n\t*** parseGccRtti() @ " << rttiAddr << std::endl;
	LOG << "\n\tRTTI @ " << rttiAddr << "\n";

	auto findRtti = gccRttis.find(rttiAddr);
	if (findRtti != gccRttis.end())
	{
		LOG << "\t[OK] already parsed" << std::endl << std::endl;
		return findRtti->second;
	}

	size_t wordSize = objf->getFileFormat()->getBytesPerWord();

	Address addr = rttiAddr;
	std::uint64_t vptrAddr = 0;
	if (!objf->getWord(addr, vptrAddr))
	{
		LOG << "\t[FAILED] vptrAddr @ " << addr <<  std::endl << std::endl;
		return nullptr;
	}
	if (vptrAddr != 0 && !objf->getSegmentFromAddress(vptrAddr))
	{
		LOG << "\t[FAILED] vptrAddr not valid = " << vptrAddr
			<<  std::endl << std::endl;
		return nullptr;
	}
	LOG << "\t\tvptr = " << vptrAddr << "\n";
	addr += wordSize;

	std::uint64_t nameAddr = 0;
	if (!objf->getWord(addr, nameAddr))
	{
		LOG << "\t[FAILED] nameAddr @ " << addr <<  std::endl << std::endl;
		return nullptr;
	}
	LOG << "\t\tname = " << nameAddr << "\n";
	std::string name;
	if (!objf->getNTBS(nameAddr, name))
	{
		LOG << "\t[FAILED] name @ " << nameAddr <<  std::endl << std::endl;
		return nullptr;
	}
	if (retdec::utils::hasNonprintableChars(name))
	{
		LOG << "\t[FAILED] name unprintable = " << name
			<<  std::endl << std::endl;
		return nullptr;
	}
	LOG << "\t\tname = " << name << "\n";
	addr += wordSize;

	Address baseAddr;
	Address addrOfBaseAddr = addr;
	std::uint64_t ba = 0;
	if (!objf->getWord(addrOfBaseAddr, ba))
	{
		LOG << "\t[NON-CRITICAL FAIL] baseAddr @ " << addrOfBaseAddr
			<< std::endl << std::endl;
	}
	else
	{
		baseAddr = ba;
		LOG << "\t\tbase = " << baseAddr << "\n";
	}
	Address flags;
	std::uint64_t f = 0;
	if (!objf->get4Byte(addr, f))
	{
		LOG << "\t[NON-CRITICAL FAIL] flags @ " << addr
			<< std::endl << std::endl;
	}
	else
	{
		flags = f;
		LOG << "\t\tflags= " << flags << "\n";
	}
	addr += 4;

	Address baseCount;
	std::uint64_t bc = 0;
	if (!objf->get4Byte(addr, bc))
	{
		LOG << "\t[NON-CRITICAL FAIL] baseCount @ " << addr
			<< std::endl << std::endl;
	}
	else
	{
		baseCount = bc;
		LOG << "\t\tb cnt= " << baseCount << "\n";
	}
	addr += 4;

	ClassTypeInfo *cti = nullptr;

	ClassTypeInfo* baseRtti = nullptr;
	if (baseAddr.isDefined() && RA->hasReferenceOnAddress(addrOfBaseAddr)
			&& baseAddr != rttiAddr)
	{
		baseRtti = parseGccRtti(objf, RA, baseAddr);
		if (baseRtti == nullptr)
		{
			LOG << "\t[FAILED] parsing base rtti @ " << baseAddr << "\n";
		}
	}

	if (baseRtti)
	{
		LOG << "\t\tSIMPLE" << "\n";

		SiClassTypeInfo *scti = new SiClassTypeInfo();
		cti = scti;
		scti->baseClassAddr = baseAddr;
		scti->baseClass = baseRtti;
	}
	else if (flags.isDefined()
			&& baseCount.isDefined()
			&& flags < (VmiClassTypeInfo::NON_DIAMOND_REPEAT_MASK
					+ VmiClassTypeInfo::DIAMOND_SHAPED_MASK))
	{
		LOG << "\t\tMULTIPLE"<< "\n";

		VmiClassTypeInfo *vcti = new VmiClassTypeInfo();
		vcti->flags = flags;
		vcti->baseCount = baseCount;

		bool failed = false;
		for (unsigned i=0; i<baseCount; ++i)
		{
			BaseClassTypeInfo bcti;

			std::uint64_t mbaseAddr = 0;
			if (!objf->getWord(addr, mbaseAddr))
			{
				LOG << "\t\t[NON-CRITICAL FAIL] mbaseAddr @ " << addr
					<< std::endl << std::endl;
				failed = true;
				break;
			}
			LOG << "\t\t\tbase = " << mbaseAddr << "\n";
			bcti.baseClassAddr = mbaseAddr;

			baseRtti = nullptr;
			if (RA->hasReferenceOnAddress(addr) && mbaseAddr != rttiAddr)
			{
				baseRtti = parseGccRtti(objf, RA, mbaseAddr);
			}
			if (baseRtti == nullptr)
			{
				LOG << "\t[FAILED] parsing rtti @ " << mbaseAddr << "\n";
				failed = true;
				break;
			}
			bcti.baseClass = baseRtti;

			addr += wordSize;
			std::uint64_t oflags = 0;
			if (!objf->get4Byte(addr, oflags))
			{
				LOG << "\t\t[NON-CRITICAL FAIL] oflags @ " << addr
					<< std::endl << std::endl;
				failed = true;
				break;
			}
			LOG << "\t\t\tflags= " << oflags << "\n";
			bcti.offsetFlags = oflags;
			addr += 4;

			vcti->baseInfo.push_back(bcti);
		}

		if (failed)
		{
			delete vcti;
		}
		else
		{
			cti = vcti;
		}
	}
	else
	{
		// this is ok -> no base class -> this class is the base.
	}

	if (cti == nullptr)
	{
		LOG << "\t\tBASE"<< "\n";

		cti = new ClassTypeInfo();
	}

	cti->vtableAddr = vptrAddr;
	cti->nameAddr = nameAddr;
	cti->address = rttiAddr;
	cti->name = name;

	gccRttis[rttiAddr] = cti;

	LOG << "\t[OK] parsed" << std::endl << std::endl;
	return gccRttis[rttiAddr];
}

void RttiAnalysis::processGccRttis()
{
	for (auto &rtti : gccRttis)
	{
		if (auto *scti = dynamic_cast<SiClassTypeInfo*>(rtti.second))
		{
			auto fIt = gccRttis.find(scti->baseClassAddr);
			assert(fIt != gccRttis.end());
			scti->baseClass = fIt->second;
		}
		else if (auto *vcti = dynamic_cast<VmiClassTypeInfo*>(rtti.second))
		{
			for (auto &bcti : vcti->baseInfo)
			{
				auto fIt = gccRttis.find(bcti.baseClassAddr);
				assert(fIt != gccRttis.end());
				bcti.baseClass = fIt->second;
			}
		}
	}
}

RTTICompleteObjectLocator* RttiAnalysis::parseMsvcObjectLocator(
		retdec::loader::Image* objfile,
		Address rttiAddr)
{
	objf = objfile;
	assert(objf);

	auto findRtti = msvcObjLocators.find(rttiAddr);
	if (findRtti != msvcObjLocators.end())
	{
		return &findRtti->second;
	}

	size_t wordSize = objf->getFileFormat()->getBytesPerWord();

	Address addr = rttiAddr;
	std::uint64_t signature1 = 0;
	if (!objf->get4Byte(addr, signature1))
		return nullptr;
	addr += 4;

	std::uint64_t offset = 0;
	if (!objf->get4Byte(addr, offset))
		return nullptr;
	addr += 4;

	std::uint64_t cdOffset = 0;
	if (!objf->get4Byte(addr, cdOffset))
		return nullptr;
	addr += 4;

	std::uint64_t typeDescriptorAddr = 0;
	if (!objf->getWord(addr, typeDescriptorAddr))
		return nullptr;
	addr += wordSize;

	std::uint64_t classDescriptorAddr = 0;
	if (!objf->getWord(addr, classDescriptorAddr))
		return nullptr;
	addr += wordSize;

	LOG << "\nRTTI @ " << rttiAddr << "\n";
	LOG << "\tsign    = " << signature1 << "\n";
	LOG << "\toff     = " << offset << "\n";
	LOG << "\tcd off  = " << cdOffset << "\n";
	LOG << "\ttd addr = " << typeDescriptorAddr << "\n";
	LOG << "\tcd addr = " << classDescriptorAddr << "\n";

	RTTICompleteObjectLocator col;

	col.address = rttiAddr;
	col.signature = signature1;
	col.offset = offset;
	col.cdOffset = cdOffset;
	col.typeDescriptorAddr = typeDescriptorAddr;
	col.classDescriptorAddr = classDescriptorAddr;

	auto td = parseMsvcTypeDescriptor(col.typeDescriptorAddr);
	if (td == nullptr)
	{
		LOG << "[FAILED] parsing type descriptor @ "
			<< col.typeDescriptorAddr << "\n";
		return nullptr;
	}
	col.typeDescriptor = td;

	auto cd = parseMsvcClassDescriptor(col.classDescriptorAddr);
	if (cd == nullptr)
	{
		LOG << "[FAILED] parsing class descriptor @ "
			<< col.classDescriptorAddr << "\n";
		return nullptr;
	}
	col.classDescriptor = cd;

	msvcObjLocators[rttiAddr] = col;
	return &msvcObjLocators[rttiAddr];
}

RTTITypeDescriptor* RttiAnalysis::parseMsvcTypeDescriptor(
		retdec::utils::Address typeDescriptorAddr)
{
	auto findTd = msvcTypeDescriptors.find(typeDescriptorAddr);
	if (findTd != msvcTypeDescriptors.end())
	{
		return &findTd->second;
	}

	auto addr = typeDescriptorAddr;
	size_t wordSize = objf->getFileFormat()->getBytesPerWord();

	std::uint64_t vtableAddr = 0;
	if (!objf->getWord(addr, vtableAddr))
		return nullptr;
	addr += wordSize;

	std::uint64_t spare = 0;
	if (!objf->getWord(addr, spare))
		return nullptr;
	addr += wordSize;

	std::string name;
	if (!objf->getNTBS(addr, name))
	{
		LOG << "\t[FAILED] name @ " << addr <<  std::endl << std::endl;
		return nullptr;
	}
	if (retdec::utils::hasNonprintableChars(name))
	{
		LOG << "\t[FAILED] name unprintable = " << name
			<< std::endl << std::endl;
		return nullptr;
	}

	LOG << "\n";
	LOG << "\tvt addr = " << vtableAddr << "\n";
	LOG << "\tspare   = " << spare << "\n";
	LOG << "\tname    = " << name << "\n";

	RTTITypeDescriptor td;

	td.address = typeDescriptorAddr;
	td.vtableAddr = vtableAddr;
	td.spare = spare;
	td.name = name;

	msvcTypeDescriptors[td.address] = td;
	return &msvcTypeDescriptors[td.address];
}

RTTIClassHierarchyDescriptor* RttiAnalysis::parseMsvcClassDescriptor(
		retdec::utils::Address classDescriptorAddr)
{
	auto findCd = msvcClassDescriptors.find(classDescriptorAddr);
	if (findCd != msvcClassDescriptors.end())
	{
		return &findCd->second;
	}

	auto addr = classDescriptorAddr;
	size_t wordSize = objf->getFileFormat()->getBytesPerWord();

	std::uint64_t signature2 = 0;
	if (!objf->get4Byte(addr, signature2))
		return nullptr;
	addr += 4;

	std::uint64_t attributes = 0;
	if (!objf->get4Byte(addr, attributes))
		return nullptr;
	addr += 4;

	std::uint64_t numBaseClasses = 0;
	if (!objf->get4Byte(addr, numBaseClasses))
		return nullptr;
	addr += 4;

	std::uint64_t baseClassArrayAddr = 0;
	if (!objf->getWord(addr, baseClassArrayAddr))
		return nullptr;
	addr += wordSize;

	addr = baseClassArrayAddr;
	std::vector<std::uint64_t> baseClassArray;
	for (unsigned i=0; i<numBaseClasses; ++i)
	{
		std::uint64_t tmp = 0;
		if (!objf->getWord(addr, tmp))
			return nullptr;
		addr += wordSize;

		baseClassArray.push_back(tmp);
	}

	LOG << "\n";
	LOG << "\tsign    = " << signature2 << "\n";
	LOG << "\tattr    = " << attributes << "\n";
	LOG << "\tbase num= " << numBaseClasses << "\n";
	LOG << "\tbase aa = " << baseClassArrayAddr << "\n";
	LOG << "\tbase a  =";
	for (auto a : baseClassArray)
		LOG << " " << a;
	LOG << "\n";

	RTTIClassHierarchyDescriptor cd;

	cd.address = classDescriptorAddr;
	cd.signature = signature2;
	cd.attributes = attributes;
	cd.baseClassArrayAddr = baseClassArrayAddr;
	for (auto a : baseClassArray)
	{
		cd.baseClassArray.push_back(a);

		auto bcd = parseMsvcBaseClassDescriptor(a);
		if (bcd == nullptr)
		{
			LOG << "[FAILED] parsing base class descriptor @ " << a << "\n";
			return nullptr;
		}
		cd.baseClasses.push_back(bcd);
	}

	msvcClassDescriptors[cd.address] = cd;
	return &msvcClassDescriptors[cd.address];
}

RTTIBaseClassDescriptor* RttiAnalysis::parseMsvcBaseClassDescriptor(
		retdec::utils::Address baseDescriptorAddr)
{
	auto findBcd = msvcBaseClassDescriptors.find(baseDescriptorAddr);
	if (findBcd != msvcBaseClassDescriptors.end())
	{
		return &findBcd->second;
	}

	auto addr = baseDescriptorAddr;
	size_t wordSize = objf->getFileFormat()->getBytesPerWord();

	std::uint64_t typeDescriptorAddr = 0;
	if (!objf->getWord(addr, typeDescriptorAddr))
		return nullptr;
	addr += wordSize;

	std::uint64_t numContainedBases = 0;
	if (!objf->get4Byte(addr, numContainedBases))
		return nullptr;
	addr += 4;

	std::uint64_t mdisp = 0;
	if (!objf->get4Byte(addr, mdisp))
		return nullptr;
	addr += 4;

	std::uint64_t pdisp = 0;
	if (!objf->get4Byte(addr, pdisp))
		return nullptr;
	addr += 4;

	std::uint64_t vdisp = 0;
	if (!objf->get4Byte(addr, vdisp))
		return nullptr;
	addr += 4;

	std::uint64_t attributes = 0;
	if (!objf->get4Byte(addr, attributes))
		return nullptr;
	addr += 4;

	LOG << "\n";
	LOG << "\t\ttd addr = " << typeDescriptorAddr << "\n";
	LOG << "\t\tnum bs  = " << numContainedBases << "\n";
	LOG << "\t\tmdistp  = " << mdisp << "\n";
	LOG << "\t\tpdisp   = " << pdisp << "\n";
	LOG << "\t\tvdisp   = " << vdisp << "\n";
	LOG << "\t\tattrs   = " << attributes << "\n";

	RTTIBaseClassDescriptor bcd;
	bcd.address = baseDescriptorAddr;
	bcd.typeDescriptorAddr = typeDescriptorAddr;
	bcd.numContainedBases = numContainedBases;
	bcd.where.mdisp = mdisp;
	bcd.where.pdisp = pdisp;
	bcd.where.vdisp = vdisp;
	bcd.attributes = attributes;

	auto td = parseMsvcTypeDescriptor(bcd.typeDescriptorAddr);
	if (td == nullptr)
	{
		LOG << "[FAILED] parsing type descriptor @ "
			<< bcd.typeDescriptorAddr << std::endl;
		return nullptr;
	}
	bcd.typeDescriptor = td;

	msvcBaseClassDescriptors[bcd.address] = bcd;
	return &msvcBaseClassDescriptors[bcd.address];
}

void RttiAnalysis::processMsvcRttis()
{

}

} // namespace bin2llvmir
} // namespace retdec
