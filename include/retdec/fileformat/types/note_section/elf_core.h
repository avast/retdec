/**
 * @file include/retdec/fileformat/types/note_section/elf_core.cpp
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
 * Class for representing information from core files
 */
class ElfCoreInfo
{
	private:
		std::uint64_t pageSize;            ///< used page size
		std::vector<FileMapEntry> fileMap; ///< parsed NT_FILE note

		std::map<std::string, std::uint64_t> registers; ///< registers state

	public:
		/// @name Setters
		/// @{
		void setPageSize(const std::uint64_t& size);
		void addFileMapEntry(const FileMapEntry& entry);
		void addRegisterEntry(
				const std::string& rName,
				const std::uint64_t& rVaue);
		/// @}

		/// @name Getters
		/// @{
		std::uint64_t getPageSize() const;
		const std::vector<FileMapEntry>& getFileMap() const;
		/// @}

		/// @name Helper methods
		/// @{
		void dump(std::ostream& outStream);
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
