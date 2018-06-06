/**
* @file src/bin2llvmir/utils/capstone.cpp
* @brief Capstone utilities.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/utils/capstone.h"

namespace retdec {
namespace bin2llvmir {
namespace capstone_utils {

std::string mode2string(const config::Architecture& arch, cs_mode m)
{
	std::string ret;

	ret += m & CS_MODE_BIG_ENDIAN
			? "CS_MODE_BIG_ENDIAN"
			: "CS_MODE_LITTLE_ENDIAN";

	if (arch.isX86())
	{
		ret += m & CS_MODE_16 ? ", CS_MODE_16" : "";
		ret += m & CS_MODE_32 ? ", CS_MODE_32" : "";
		ret += m & CS_MODE_64 ? ", CS_MODE_64" : "";
	}
	else if (arch.isMipsOrPic32())
	{
		ret += m & CS_MODE_MIPS32 ? ", CS_MODE_MIPS32" : "";
		ret += m & CS_MODE_MIPS64 ? ", CS_MODE_MIPS64" : "";
		ret += m & CS_MODE_MICRO ? ", CS_MODE_MICRO" : "";
		ret += m & CS_MODE_MIPS3 ? ", CS_MODE_MIPS3" : "";
		ret += m & CS_MODE_MIPS32R6 ? ", CS_MODE_MIPS32R6" : "";
		ret += m & CS_MODE_MIPS2 ? ", CS_MODE_MIPS2" : "";
	}
	else if (arch.isArmOrThumb())
	{
		ret += m & CS_MODE_THUMB ? ", CS_MODE_THUMB" : ", CS_MODE_ARM";
		ret += m & CS_MODE_MCLASS ? ", CS_MODE_MCLASS" : "";
		ret += m & CS_MODE_V8 ? ", CS_MODE_V8" : "";
	}
	else if (arch.isPpc())
	{
		ret += m & CS_MODE_64 ? ", CS_MODE_64" : ", CS_MODE_32";
		ret += m & CS_MODE_QPX ? ", CS_MODE_QPX" : "";
	}
	else
	{
		assert(false);
	}

	return ret;
}

} // namespace capstone_utils
} // namespace bin2llvmir
} // namespace retdec
