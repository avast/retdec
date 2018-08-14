/**
 * @file src/fileformat/types/note_section/elf_core.cpp
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
 * Add one aux. vector entry
 * @param entry vector entry
 */
void ElfCoreInfo::addAuxVectorEntry(const AuxVectorEntry& entry)
{
	auxVector.emplace_back(entry);
}

/**
 * Add one prstatus struct
 * @param info prstatus struct entry
 */
void ElfCoreInfo::addPrStatusInfo(const PrStatusInfo& info)
{
	prstatusInfos.emplace_back(info);
}

/**
 * Set name off original application
 * @param name name of application
 */
void ElfCoreInfo::setAppName(const std::string& name)
{
	appName = name;
}

/**
 * Set original command line string
 * @param line command line
 */
void ElfCoreInfo::setCmdLine(const std::string& line)
{
	cmdLine = line;
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
 * Get auxiliary vector
 * @return auxiliary vector
 */
const std::vector<AuxVectorEntry>& ElfCoreInfo::getAuxVector() const
{
	return auxVector;
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

	if(!prstatusInfos.empty())
	{
		outStream << "Prstatus info \n";
		for(const auto& info : prstatusInfos)
		{
			outStream
				<< "PID  : " << std::dec << info.pid << "\n"
				<< "PPID : " << info.ppid << "\n"
				<< "Registers info: \n";
			for(const auto& entry : info.registers)
			{
				outStream
					<< "Name  : " << entry.first << "\t"
					<< "Value : 0x" << std::hex << entry.second << "\n";
			}
		}
	}

	if(!appName.empty() || !cmdLine.empty())
	{
		outStream << "Prpsinfo info \n";
		outStream << "Name : " << appName << "\n";
		outStream << "Line : " << cmdLine << "\n";
	}

	if(!auxVector.empty())
	{
		outStream << "Auxf info (" << auxVector.size() << ")\n";
		for(const auto& entry : auxVector)
		{
			outStream
				<< "Name  : " << entry.first << "\t"
				<< "Value : " << entry.second << "\n";
		}
	}
}

} // namespace fileformat
} // namespace retdec
