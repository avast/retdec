/**
 * @file src/fileformat/types/note_section/elf_note.cpp
 * @brief Class for ELF core data.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/types/note_section/elf_core.h"

namespace retdec {
namespace fileformat {


/**
 * Add one entry to core file map
 * @param entry map entry
 */
void ElfCoreInfo::addFileMapEntry(const FileMapEntry& entry)
{
	fileMap.emplace_back(entry);
}

/**
 * Set page size
 * @param size page size
 */
void ElfCoreInfo::setPageSize(const std::size_t& size)
{
	pageSize = size;
}


void ElfCoreInfo::dump(std::ostream& outStream)
{
	// dump file map
	outStream << "Core file info dump\n===================\n";

	if(!fileMap.empty())
	{
		outStream << "Mapped files info:\nPage size: " << pageSize << "\n";
		for(const auto& entry : fileMap)
		{
			outStream
				<< "Start : " << std::hex << entry.startAddr << "\n"
				<< "End   : " << std::hex << entry.endAddr << "\n"
				<< "Page  : " << std::hex << entry.pageOffset << "\n"
				<< "Path  : " << entry.filePath << "\n--------------------\n";
		}
	}
}


} // namespace fileformat
} // namespace retdec
