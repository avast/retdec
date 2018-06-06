/**
 * @file src/rtti-finder/rtti/rtti_msvc_parser.cpp
 * @brief Parse C++ MSVC RTTI structures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>

#include "retdec/loader/loader/image.h"
#include "retdec/rtti-finder/rtti/rtti_msvc_parser.h"
#include "retdec/utils/string.h"

#define LOG \
	if (!debug_enabled) {} \
	else std::cout << std::showbase
const bool debug_enabled = false;

using namespace retdec::utils;

namespace retdec {
namespace rtti_finder {

RTTITypeDescriptor* parseMsvcTypeDescriptor(
		const retdec::loader::Image* img,
		RttiMsvc& rttis,
		retdec::utils::Address typeDescriptorAddr)
{
	auto findTd = rttis.typeDescriptors.find(typeDescriptorAddr);
	if (findTd != rttis.typeDescriptors.end())
	{
		return &findTd->second;
	}

	auto addr = typeDescriptorAddr;
	size_t wordSize = img->getBytesPerWord();

	std::uint64_t vtableAddr = 0;
	if (!img->getWord(addr, vtableAddr))
		return nullptr;
	addr += wordSize;

	std::uint64_t spare = 0;
	if (!img->getWord(addr, spare))
		return nullptr;
	addr += wordSize;

	std::string name;
	if (!img->getNTBS(addr, name))
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

	RTTITypeDescriptor& td = rttis.typeDescriptors.emplace(
			typeDescriptorAddr,
			RTTITypeDescriptor()).first->second;

	td.address = typeDescriptorAddr;
	td.vtableAddr = vtableAddr;
	td.spare = spare;
	td.name = name;

	return &td;
}

RTTIBaseClassDescriptor* parseMsvcBaseClassDescriptor(
		const retdec::loader::Image* img,
		RttiMsvc& rttis,
		retdec::utils::Address baseDescriptorAddr)
{
	auto findBcd = rttis.baseClassDescriptors.find(baseDescriptorAddr);
	if (findBcd != rttis.baseClassDescriptors.end())
	{
		return &findBcd->second;
	}

	auto addr = baseDescriptorAddr;
	size_t wordSize = img->getBytesPerWord();

	std::uint64_t typeDescriptorAddr = 0;
	if (!img->getWord(addr, typeDescriptorAddr))
		return nullptr;
	addr += wordSize;

	std::uint64_t numContainedBases = 0;
	if (!img->get4Byte(addr, numContainedBases))
		return nullptr;
	addr += 4;

	std::uint64_t mdisp = 0;
	if (!img->get4Byte(addr, mdisp))
		return nullptr;
	addr += 4;

	std::uint64_t pdisp = 0;
	if (!img->get4Byte(addr, pdisp))
		return nullptr;
	addr += 4;

	std::uint64_t vdisp = 0;
	if (!img->get4Byte(addr, vdisp))
		return nullptr;
	addr += 4;

	std::uint64_t attributes = 0;
	if (!img->get4Byte(addr, attributes))
		return nullptr;
	addr += 4;

	LOG << "\n";
	LOG << "\t\ttd addr = " << typeDescriptorAddr << "\n";
	LOG << "\t\tnum bs  = " << numContainedBases << "\n";
	LOG << "\t\tmdistp  = " << mdisp << "\n";
	LOG << "\t\tpdisp   = " << pdisp << "\n";
	LOG << "\t\tvdisp   = " << vdisp << "\n";
	LOG << "\t\tattrs   = " << attributes << "\n";

	auto td = parseMsvcTypeDescriptor(img, rttis, typeDescriptorAddr);
	if (td == nullptr)
	{
		LOG << "[FAILED] parsing type descriptor @ "
			<< typeDescriptorAddr << std::endl;
		return nullptr;
	}

	RTTIBaseClassDescriptor& bcd = rttis.baseClassDescriptors.emplace(
			baseDescriptorAddr,
			RTTIBaseClassDescriptor()).first->second;

	bcd.address = baseDescriptorAddr;
	bcd.typeDescriptorAddr = typeDescriptorAddr;
	bcd.numContainedBases = numContainedBases;
	bcd.where.mdisp = mdisp;
	bcd.where.pdisp = pdisp;
	bcd.where.vdisp = vdisp;
	bcd.attributes = attributes;
	bcd.typeDescriptor = td;

	return &bcd;
}

RTTIClassHierarchyDescriptor* parseMsvcClassDescriptor(
		const retdec::loader::Image* img,
		RttiMsvc& rttis,
		retdec::utils::Address classDescriptorAddr)
{
	auto findCd = rttis.classDescriptors.find(classDescriptorAddr);
	if (findCd != rttis.classDescriptors.end())
	{
		return &findCd->second;
	}

	auto addr = classDescriptorAddr;
	size_t wordSize = img->getBytesPerWord();

	std::uint64_t signature2 = 0;
	if (!img->get4Byte(addr, signature2))
		return nullptr;
	addr += 4;

	std::uint64_t attributes = 0;
	if (!img->get4Byte(addr, attributes))
		return nullptr;
	addr += 4;

	std::uint64_t numBaseClasses = 0;
	if (!img->get4Byte(addr, numBaseClasses))
		return nullptr;
	addr += 4;

	std::uint64_t baseClassArrayAddr = 0;
	if (!img->getWord(addr, baseClassArrayAddr))
		return nullptr;
	addr += wordSize;

	addr = baseClassArrayAddr;
	std::vector<std::uint64_t> baseClassArray;
	for (unsigned i=0; i<numBaseClasses; ++i)
	{
		std::uint64_t tmp = 0;
		if (!img->getWord(addr, tmp))
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

		auto bcd = parseMsvcBaseClassDescriptor(img, rttis, a);
		if (bcd == nullptr)
		{
			LOG << "[FAILED] parsing base class descriptor @ " << a << "\n";
			return nullptr;
		}
		cd.baseClasses.push_back(bcd);
	}

	return &rttis.classDescriptors.emplace(cd.address, cd).first->second;
}

RTTICompleteObjectLocator* parseMsvcObjectLocator(
		const retdec::loader::Image* img,
		RttiMsvc& rttis,
		retdec::utils::Address rttiAddr)
{
	auto findRtti = rttis.objLocators.find(rttiAddr);
	if (findRtti != rttis.objLocators.end())
	{
		return &findRtti->second;
	}

	size_t wordSize = img->getBytesPerWord();

	Address addr = rttiAddr;
	std::uint64_t signature1 = 0;
	if (!img->get4Byte(addr, signature1))
		return nullptr;
	addr += 4;

	std::uint64_t offset = 0;
	if (!img->get4Byte(addr, offset))
		return nullptr;
	addr += 4;

	std::uint64_t cdOffset = 0;
	if (!img->get4Byte(addr, cdOffset))
		return nullptr;
	addr += 4;

	std::uint64_t typeDescriptorAddr = 0;
	if (!img->getWord(addr, typeDescriptorAddr))
		return nullptr;
	addr += wordSize;

	std::uint64_t classDescriptorAddr = 0;
	if (!img->getWord(addr, classDescriptorAddr))
		return nullptr;
	addr += wordSize;

	LOG << "\nRTTI @ " << rttiAddr << "\n";
	LOG << "\tsign    = " << signature1 << "\n";
	LOG << "\toff     = " << offset << "\n";
	LOG << "\tcd off  = " << cdOffset << "\n";
	LOG << "\ttd addr = " << typeDescriptorAddr << "\n";
	LOG << "\tcd addr = " << classDescriptorAddr << "\n";

	auto td = parseMsvcTypeDescriptor(img, rttis, typeDescriptorAddr);
	if (td == nullptr)
	{
		LOG << "[FAILED] parsing type descriptor @ "
			<< typeDescriptorAddr << "\n";
		return nullptr;
	}

	auto cd = parseMsvcClassDescriptor(img, rttis, classDescriptorAddr);
	if (cd == nullptr)
	{
		LOG << "[FAILED] parsing class descriptor @ "
			<< classDescriptorAddr << "\n";
		return nullptr;
	}

	RTTICompleteObjectLocator& col = rttis.objLocators.emplace(
			rttiAddr,
			RTTICompleteObjectLocator()).first->second;

	col.address = rttiAddr;
	col.signature = signature1;
	col.offset = offset;
	col.cdOffset = cdOffset;
	col.typeDescriptorAddr = typeDescriptorAddr;
	col.classDescriptorAddr = classDescriptorAddr;
	col.typeDescriptor = td;
	col.classDescriptor = cd;

	return &col;
}

/**
 * Pointer to RTTI entry if parsed ok, @c nullptr otherwise.
 */
RTTICompleteObjectLocator* parseMsvcRtti(
		const retdec::loader::Image* img,
		RttiMsvc& rttis,
		retdec::utils::Address rttiAddr)
{
	return parseMsvcObjectLocator(img, rttis, rttiAddr);
}

} // namespace rtti_finder
} // namespace retdec
