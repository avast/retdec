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
 * Add one entry to register map
 * @param rName name of register
 * @param rVaue value of register
 */
void ElfCoreInfo::addRegisterEntry(
		const std::string& rName,
		const uint64_t& rVaue)
{
	registers.emplace(rName, rVaue);
}

/**
 * Set page size specified in NT_FILE note
 * @param size page size
 */
void ElfCoreInfo::setPageSize(const uint64_t& size)
{
	pageSize = size;
}

/**
 * Get page size specified in NT_FILE note
 * @return page size
 */
uint64_t ElfCoreInfo::getPageSize() const
{
	return pageSize;
}

/**
 * Get core file map from NT_FILE note
 * @return core file map
 */
const std::vector<FileMapEntry>& ElfCoreInfo::getFileMap() const
{
	return fileMap;
}

/**
 * Dump CORE file info
 * @param outStream target output stream
 */
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

	if(!registers.empty())
	{
		outStream << "Registers info \n";
		for(const auto& entry : registers)
		{
			outStream
				<< "Name  : " << entry.first << "\t"
				<< "Value : 0x" << std::hex << entry.second << "\n";
		}
	}
}


} // namespace fileformat
} // namespace retdec
