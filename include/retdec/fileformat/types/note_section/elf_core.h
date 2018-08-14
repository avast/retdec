/**
 * @file include/retdec/fileformat/types/note_section/elf_core.h
 * @brief Class for ELF core data.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_NOTE_SECTION_ELF_CORE_H
#define RETDEC_FILEFORMAT_TYPES_NOTE_SECTION_ELF_CORE_H

#include <string>
#include <vector>
#include <map>

#include "retdec/utils/address.h"

namespace retdec {
namespace fileformat {

using RegisterMap = std::map<std::string, std::uint64_t>;
using AuxVectorEntry = std::pair<std::uint64_t, std::uint64_t>;

/**
 * Entry for one mapped file in NT_FILE note
 */
class FileMapEntry
{
	public:
		std::uint64_t startAddr;  ///< start address of mapped segment
		std::uint64_t endAddr;    ///< end address of mapped segment
		std::uint64_t pageOffset; ///< page offset
		std::string filePath;     ///< full path to mapped file
};

/**
 * Class representing one NT_PRSTATUS note
 *
 * @note This structure is far from complete but we will add support only for
 * things we can use somehow for decompilation purposes.
 */
class PrStatusInfo
{
	public:
		std::uint64_t pid;     ///< process ID
		std::uint64_t ppid;    ///< parent process ID
		RegisterMap registers; ///< registers state
};

/**
 * Class for representing information from core files
 */
class ElfCoreInfo
{
	private:
		// NT_FILE
		std::uint64_t pageSize;            ///< used page size
		std::vector<FileMapEntry> fileMap; ///< parsed file map

		// NT_PRSTATUS
		std::vector<PrStatusInfo> prstatusInfos; ///< prstatus structures

		// NT_PRPSINFO
		std::string appName; ///< original application name
		std::string cmdLine; ///< command line

		// NT_AUXV
		std::vector<AuxVectorEntry> auxVector; /// auxiliary vector

	public:
		/// @name Setters
		/// @{
		void setPageSize(const std::uint64_t& size);
		void addFileMapEntry(const FileMapEntry& entry);
		void addAuxVectorEntry(const AuxVectorEntry& entry);
		void addPrStatusInfo(const PrStatusInfo& info);
		void setAppName(const std::string& name);
		void setCmdLine(const std::string& line);
		/// @}

		/// @name Getters
		/// @{
		std::uint64_t getPageSize() const;
		const std::vector<FileMapEntry>& getFileMap() const;
		const std::vector<AuxVectorEntry>& getAuxVector() const;
		/// @}

		/// @name Helper methods
		/// @{
		void dump(std::ostream& outStream);
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
