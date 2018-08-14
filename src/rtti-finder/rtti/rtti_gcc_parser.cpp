/**
 * @file src/rtti-finder/rtti/rtti_gcc_parser.cpp
 * @brief Parse C++ GCC/Clang RTTI structures.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>

#include "retdec/loader/loader/image.h"
#include "retdec/rtti-finder/rtti/rtti_gcc_parser.h"
#include "retdec/utils/string.h"

#define LOG \
	if (!debug_enabled) {} \
	else std::cout << std::showbase << std::hex
const bool debug_enabled = false;

using namespace retdec::utils;

/**
 * @note This method is defined outside the namespace retdec::rtti_finder with
 *       explicit namespace declarations to help Doxygen and prevent it from
 *       generating "no matching file member found for" warnings.
 */
std::shared_ptr<retdec::rtti_finder::ClassTypeInfo> retdec::rtti_finder::parseGccRtti(
		const retdec::loader::Image* img,
		retdec::rtti_finder::RttiGcc& rttis,
		retdec::utils::Address rttiAddr)
{
	LOG << "\n\t" << "parseGccRtti() @ " << rttiAddr << std::endl;

	auto findRtti = rttis.find(rttiAddr);
	if (findRtti != rttis.end())
	{
		LOG << "\t[OK] already parsed" << std::endl << std::endl;
		return findRtti->second;
	}

	size_t wordSize = img->getBytesPerWord();

	Address addr = rttiAddr;
	std::uint64_t vptrAddr = 0;
	if (!img->getWord(addr, vptrAddr))
	{
		LOG << "\t[FAILED] vptrAddr @ " << addr <<  std::endl << std::endl;
		return nullptr;
	}
	if (vptrAddr != 0 && !img->getSegmentFromAddress(vptrAddr))
	{
		LOG << "\t[FAILED] vptrAddr not valid = " << vptrAddr
			 << " @ " << addr << std::endl << std::endl;
		return nullptr;
	}
	LOG << "\t\tvptr = " << vptrAddr << "\n";
	addr += wordSize;

	std::uint64_t nameAddr = 0;
	if (!img->getWord(addr, nameAddr))
	{
		LOG << "\t[FAILED] nameAddr @ " << addr <<  std::endl << std::endl;
		return nullptr;
	}
	LOG << "\t\tname = " << nameAddr << "\n";
	std::string name;
	if (!img->getNTBS(nameAddr, name))
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
	if (!img->getWord(addrOfBaseAddr, ba))
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
	if (!img->get4Byte(addr, f))
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
	if (!img->get4Byte(addr, bc))
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

	std::shared_ptr<ClassTypeInfo> cti;

	std::shared_ptr<ClassTypeInfo> baseRtti;
	if (baseAddr.isDefined() && img->isPointer(addrOfBaseAddr)
			&& baseAddr != rttiAddr)
	{
		baseRtti = parseGccRtti(img, rttis, baseAddr);
		if (baseRtti == nullptr)
		{
			LOG << "\t[FAILED] parsing base rtti @ " << baseAddr << "\n";
		}
	}

	if (baseRtti)
	{
		LOG << "\t\tSIMPLE" << "\n";

		auto scti = std::make_shared<SiClassTypeInfo>();
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

		auto vcti = std::make_shared<VmiClassTypeInfo>();
		vcti->flags = flags;
		vcti->baseCount = baseCount;

		bool failed = false;
		for (unsigned i=0; i<baseCount; ++i)
		{
			BaseClassTypeInfo bcti;

			std::uint64_t mbaseAddr = 0;
			if (!img->getWord(addr, mbaseAddr))
			{
				LOG << "\t\t[NON-CRITICAL FAIL] mbaseAddr @ " << addr
					<< std::endl << std::endl;
				failed = true;
				break;
			}
			LOG << "\t\t\tbase = " << mbaseAddr << "\n";
			bcti.baseClassAddr = mbaseAddr;

			baseRtti = nullptr;
			if (img->isPointer(addr) && mbaseAddr != rttiAddr)
			{
				baseRtti = parseGccRtti(img, rttis, mbaseAddr);
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
			if (!img->get4Byte(addr, oflags))
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

		if (!failed)
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
		cti = std::make_shared<ClassTypeInfo>();
	}

	cti->vtableAddr = vptrAddr;
	cti->nameAddr = nameAddr;
	cti->address = rttiAddr;
	cti->name = name;

	LOG << "\t[OK] parsed" << std::endl << std::endl;

	return rttis.emplace(rttiAddr, cti).first->second;
}

/**
 * @note This method is defined outside the namespace retdec::rtti_finder with
 *       explicit namespace declarations to help Doxygen and prevent it from
 *       generating "no matching file member found for" warnings.
 */
void retdec::rtti_finder::finalizeGccRtti(retdec::rtti_finder::RttiGcc& rttis)
{
	for (auto &rtti : rttis)
	{
		if (auto scti = std::dynamic_pointer_cast<SiClassTypeInfo>(rtti.second))
		{
			auto fIt = rttis.find(scti->baseClassAddr);
			if (fIt != rttis.end())
			{
				scti->baseClass = fIt->second;
			}
		}
		else if (auto vcti = std::dynamic_pointer_cast<VmiClassTypeInfo>(rtti.second))
		{
			for (auto &bcti : vcti->baseInfo)
			{
				auto fIt = rttis.find(bcti.baseClassAddr);
				if (fIt != rttis.end())
				{
					bcti.baseClass = fIt->second;
				}
			}
		}
	}
}
