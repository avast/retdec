/**
 * @file src/fileinfo/file_information/file_information_types/elf_core.cpp
 * @brief ElfCore.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_information/file_information_types/elf_core.h"

using namespace retdec::fileformat;

namespace fileinfo {

ElfCore::ElfCore()
{
}

bool ElfCore::hasAuxVector() const
{
	return !auxVec.empty();
}

const std::vector<AuxVectorEntry>& ElfCore::getAuxVector() const
{
	return auxVec;
}

void ElfCore::addAuxVectorEntry(
		const std::string& name,
		const std::size_t& value)
{
	auxVec.emplace_back(name, value);
}

} // namespace fileinfo
