/**
 * @file src/capstone2llvmir/capstone_utils.h
 * @brief Utility functions for types, enums, etc. defined in Capstone.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CAPSTONE2LLVMIR_CAPSTONE_UTILS_H
#define RETDEC_CAPSTONE2LLVMIR_CAPSTONE_UTILS_H

#include <map>
#include <string>

#include <capstone/capstone.h>

namespace retdec {
namespace capstone2llvmir {

static std::map<cs_arch, std::string> capstoneArchStringMap =
{
		{CS_ARCH_ARM, "CS_ARCH_ARM"},
		{CS_ARCH_ARM64, "CS_ARCH_ARM64"},
		{CS_ARCH_MIPS, "CS_ARCH_MIPS"},
		{CS_ARCH_X86, "CS_ARCH_X86"},
		{CS_ARCH_PPC, "CS_ARCH_PPC"},
		{CS_ARCH_SPARC, "CS_ARCH_SPARC"},
		{CS_ARCH_SYSZ, "CS_ARCH_SYSZ"},
		{CS_ARCH_XCORE, "CS_ARCH_XCORE"},
		{CS_ARCH_MAX, "CS_ARCH_MAX"},
		{CS_ARCH_ALL, "CS_ARCH_ALL"}
};

inline std::string capstoneArchToString(cs_arch a)
{
	auto fIt = capstoneArchStringMap.find(a);
	return fIt != capstoneArchStringMap.end() ? fIt->second : std::string();
}

static std::map<cs_mode, std::string> capstoneModeStringMap =
{
		{CS_MODE_LITTLE_ENDIAN, "CS_MODE_LITTLE_ENDIAN"},
		{CS_MODE_ARM, "CS_MODE_ARM"},
		{CS_MODE_16, "CS_MODE_16"},
		{CS_MODE_32, "CS_MODE_32"},
		{CS_MODE_64, "CS_MODE_64"},
		{CS_MODE_THUMB, "CS_MODE_THUMB"},
		{CS_MODE_MCLASS, "CS_MODE_MCLASS"},
		{CS_MODE_V8, "CS_MODE_V8"},
		{CS_MODE_MICRO, "CS_MODE_MICRO"},
		{CS_MODE_MIPS3, "CS_MODE_MIPS3"},
		{CS_MODE_MIPS32R6, "CS_MODE_MIPS32R6"},
		{CS_MODE_V9, "CS_MODE_V9"},
		{CS_MODE_BIG_ENDIAN, "CS_MODE_BIG_ENDIAN"},
		{CS_MODE_MIPS32, "CS_MODE_MIPS32"},
		{CS_MODE_MIPS64, "CS_MODE_MIPS64"}
};

inline std::string capstoneModeToString(cs_mode m)
{
	auto fIt = capstoneModeStringMap.find(m);
	return fIt != capstoneModeStringMap.end() ? fIt->second : std::string();
}

} // namespace capstone2llvmir
} // namespace retdec

#endif
