/**
 * @file src/fileinfo/file_information/file_information_types/elf_core.cpp
 * @brief ElfCore.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_information/file_information_types/elf_core.h"

namespace fileinfo {

ElfCore::ElfCore()
{
}

bool ElfCore::hasAuxVector() const
{
	return !auxVec.empty();
}

bool ElfCore::hasFileMap() const
{
	return !fileMap.empty();
}

const std::vector<AuxVectorEntry>& ElfCore::getAuxVector() const
{
	return auxVec;
}

const std::vector<FileMapEntry>& ElfCore::getFileMap() const
{
	return fileMap;
}

void ElfCore::addFileMapEntry(const FileMapEntry& entry)
{
	fileMap.emplace_back(entry);
}

void ElfCore::addAuxVectorEntry(
		const std::string& name,
		const std::uint64_t& value)
{
	auxVec.emplace_back(name, value);
}

} // namespace fileinfo
