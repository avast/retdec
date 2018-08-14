/**
 * @file src/rtti-finder/vtable/vtable_finder.cpp
 * @brief Find vtable structures in @c Image.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>

#include "retdec/loader/loader/image.h"
#include "retdec/rtti-finder/rtti/rtti_gcc_parser.h"
#include "retdec/rtti-finder/rtti/rtti_msvc_parser.h"
#include "retdec/rtti-finder/vtable/vtable_finder.h"

#define LOG \
	if (!debug_enabled) {} \
	else std::cout << std::showbase
const bool debug_enabled = false;

using namespace retdec::utils;
using namespace retdec::rtti_finder;

void findPossibleVtables(
		const retdec::loader::Image* img,
		std::set<retdec::utils::Address>& possibleVtables,
		bool gcc)
{
	auto wordSz = img->getBytesPerWord();

	for (auto& seg : img->getSegments())
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
			if (!img->getWord(addr, val))
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

			if (!img->isPointer(item1)
					|| !img->isPointer(item2))
			{
				addr += wordSz;
				continue;
			}

			possibleVtables.insert(item2);
			addr = item2;
		}
	}
}

/**
 * @return @c True if vtable ok and can be used, @c false if it should
 * be thrown away.
 */
bool fillVtable(
		const retdec::loader::Image* img,
		std::set<retdec::utils::Address>& processedAddresses,
		Address a,
		Vtable& vt)
{
	LOG << "\t\t" << "fillVtable() @ " << a << std::endl;
	std::set<retdec::utils::Address> items;

	bool isThumb = false;
	auto bpw = img->getBytesPerWord();
	std::uint64_t ptr = 0;
	auto isPtr = img->isPointer(a, &ptr);
	while (true)
	{
		if (!isPtr)
		{
			LOG << "\t\t\t" << a << " @ !isPtr" << std::endl;
			break;
		}
		if (img->getFileFormat()->isArm() && ptr % 2)
		{
			--ptr;
			isThumb = true;
		}
		if (processedAddresses.find(a) != processedAddresses.end())
		{
			LOG << "\t\t\t" << a << " @ !processedAddresses" << std::endl;
			break;
		}
		auto* seg = img->getSegmentFromAddress(ptr);
		if (seg == nullptr
				|| seg->getSecSeg() == nullptr
				|| !seg->getSecSeg()->isSomeCode())
		{
			LOG << "\t\t\t" << a << " @ !isSomeCode" << std::endl;
			break;
		}

		// All items in vtable must be unique (really???).
		//
		if (items.find(ptr) != items.end())
		{
			LOG << "\t\t\t" << a << " @ !unique" << std::endl;
			return false;
		}

		LOG << "\t\t\t" << a << " @ OK" << std::endl;
		vt.virtualFncAddresses.emplace_back(VtableItem(ptr, isThumb));
		items.insert(ptr);
		processedAddresses.insert(a);

		a += bpw;
		isPtr = img->isPointer(a, &ptr);
	}

	if (vt.virtualFncAddresses.empty())
	{
		LOG << "\t\t\t" << "===> FAIL" << std::endl;
		return false;
	}

	LOG << "\t\t\t" << "===> OK" << std::endl;
	return true;
}

/**
 * @note This method is defined outside the namespace retdec::rtti_finder with
 *       explicit namespace declarations to help Doxygen and prevent it from
 *       generating "no matching file member found for" warnings.
 */
void retdec::rtti_finder::findGccVtables(
		const retdec::loader::Image* img,
		retdec::rtti_finder::VtablesGcc& vtables,
		retdec::rtti_finder::RttiGcc& rttis)
{
	std::set<retdec::utils::Address> possibleVtables;
	findPossibleVtables(img, possibleVtables, true);

	std::set<retdec::utils::Address> processedAddresses;
	for (auto addr : possibleVtables)
	{
		LOG << "\t" << "possible vtable @ " << addr << std::endl;
		retdec::rtti_finder::VtableGcc vt(addr);

		if (!fillVtable(img, processedAddresses, addr, vt))
		{
			LOG << "\t\t" << "fillVtable() failed" << std::endl;
			continue;
		}

		auto rttiPtrAddr = addr - img->getBytesPerWord();
		std::uint64_t rttiAddr = 0;
		if (img->getWord(rttiPtrAddr, rttiAddr))
		{
			vt.rttiAddress = rttiAddr;
			vt.rtti = parseGccRtti(img, rttis, vt.rttiAddress);
			if (vt.rtti == nullptr)
			{
				LOG << "\t\t" << "parseGccRtti() failed" << std::endl;
				continue;
			}
		}
		else
		{
			continue;
		}

		vtables.emplace(addr, vt);
	}

	LOG << "\t\t" << "vtable OK" << std::endl;
	finalizeGccRtti(rttis);
}

/**
 * @note This method is defined outside the namespace retdec::rtti_finder with
 *       explicit namespace declarations to help Doxygen and prevent it from
 *       generating "no matching file member found for" warnings.
 */
void retdec::rtti_finder::findMsvcVtables(
		const retdec::loader::Image* img,
		retdec::rtti_finder::VtablesMsvc& vtables,
		retdec::rtti_finder::RttiMsvc& rttis)
{
	std::set<retdec::utils::Address> possibleVtables;
	findPossibleVtables(img, possibleVtables, false);

	std::set<retdec::utils::Address> processedAddresses;
	for (auto addr : possibleVtables)
	{
		retdec::rtti_finder::VtableMsvc vt(addr);

		if (!fillVtable(img, processedAddresses, addr, vt))
		{
			continue;
		}

		auto rttiPtrAddr = addr - img->getBytesPerWord();
		std::uint64_t rttiAddr = 0;
		if (img->getWord(rttiPtrAddr, rttiAddr))
		{
			vt.objLocatorAddress = rttiAddr;
			vt.rtti = parseMsvcRtti(img, rttis, vt.objLocatorAddress);
			if (vt.rtti == nullptr)
			{
				continue;
			}
		}
		else
		{
			continue;
		}

		vtables.emplace(addr, vt);
	}
}
