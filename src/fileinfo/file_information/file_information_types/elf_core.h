/**
 * @file src/fileinfo/file_information/file_information_types/elf_core.h
 * @brief ElfNotes.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_ELF_CORE_H
#define FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_ELF_CORE_H

#include <string>
#include <vector>

namespace fileinfo {

using AuxVectorEntry = std::pair<std::string, std::uint64_t>;

/**
 * One entry in file map.
 */
class FileMapEntry
{
	public:
		std::uint64_t address;
		std::uint64_t size;
		std::uint64_t page;
		std::string path;
};

/**
 * Class for ELF core files
 */
class ElfCore
{
	private:
		std::vector<AuxVectorEntry> auxVec;
		std::vector<FileMapEntry> fileMap;

	public:
		ElfCore();
		~ElfCore() = default;

		/// @name Queries
		/// @{
		bool hasAuxVector() const;
		bool hasFileMap() const;
		/// @}

		/// @name Getters
		/// @{
		const std::vector<AuxVectorEntry>& getAuxVector() const;
		const std::vector<FileMapEntry>& getFileMap() const;
		/// @}

		/// @name Setters
		/// @{
		void addFileMapEntry(const FileMapEntry& entry);
		void addAuxVectorEntry(
				const std::string& name,
				const std::uint64_t& value);
		/// @}
};

} // namespace fileinfo

#endif
