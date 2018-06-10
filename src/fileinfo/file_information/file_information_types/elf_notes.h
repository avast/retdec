/**
 * @file src/fileinfo/file_information/file_information_types/elf_notes.h
 * @brief ElfNotes.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_ELF_NOTES_H
#define FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_ELF_NOTES_H

#include <vector>

#include "retdec/fileformat/types/note_section/elf_notes.h"

namespace fileinfo {

/**
 * Class for one ELF note entry
 */
class ElfNoteEntry
{
	public:
		std::string owner;
		std::size_t type;
		std::size_t dataOffset;
		std::size_t dataLength;
		std::string description;
};

/**
 * Class for ELF notes
 */
class ElfNotes
{
	private:
		std::string sectionName;
		std::size_t secSegOffset;
		std::size_t secSegLength;
		std::string errorMessage;
		std::vector<ElfNoteEntry> notes;

	public:
		ElfNotes();
		~ElfNotes() = default;

		/// @name Getters
		/// @{
		std::string getSectionName() const;
		std::size_t getSecSegOffset() const;
		std::size_t getSecSegLength() const;
		std::size_t getNumberOfNotes() const;
		const std::string& getErrorMessage() const;
		const std::vector<ElfNoteEntry>& getNotes() const;
		/// @}

		/// @name Query methods
		/// @{
		bool isNamedSection() const;
		bool isMalformed() const;
		/// @}

		/// @name Setters
		/// @{
		void setSectionName(const std::string& name);
		void setSecSegOffset(const std::size_t& offset);
		void setSecSegLength(const std::size_t& length);
		void setErrorMessage(const std::string& message);
		void addNoteEntry(const ElfNoteEntry& noteEntry);
		/// @}
};

} // namespace fileinfo

#endif
