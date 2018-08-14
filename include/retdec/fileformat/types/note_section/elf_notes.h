/**
 * @file include/retdec/fileformat/types/note_section/elf_notes.h
 * @brief Class for ELF note section (segment).
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_NOTE_SECTION_ELF_NOTE_H
#define RETDEC_FILEFORMAT_TYPES_NOTE_SECTION_ELF_NOTE_H

#include <string>
#include <vector>

#include "retdec/fileformat/types/sec_seg/sec_seg.h"

namespace retdec {
namespace fileformat {

/**
 * Class for one ELF note section or segment entry
 */
class ElfNoteEntry
{
	public:
		std::string name; ///< interpreted name (owner)
		std::size_t type; ///< owner specific type

		// Type must be combined with name to tell how to interpret data

		std::size_t dataOffset; ///< file offset of note data
		std::size_t dataLength; ///< length of note data

		/// @name Query methods
		/// @{
		bool isEmptyNote() const;
		/// @}
};

/**
 * Class describing one ELF note section or segment
 */
class ElfNoteSecSeg
{
	private:
		const SecSeg* secSeg;            ///< associated section or segment
		std::vector<ElfNoteEntry> notes; ///< notes in segment or section

		bool malformed = false; ///< set to @c true if notes are malformed
		std::string error;      ///< possible error message

	public:
		/// @name  Constructors and destructor
		/// @{
		ElfNoteSecSeg(const SecSeg* assocSecSeg);
		~ElfNoteSecSeg();
		/// @}

		/// @name Setters
		/// @{
		void setMalformed(const std::string& message = "corrupted note");
		/// @}

		/// @name Add notes
		/// @{
		void addNote(ElfNoteEntry&& note);
		void addNote(const ElfNoteEntry& note);
		/// @}

		/// @name Getters
		/// @{
		std::vector<ElfNoteEntry> getNotes() const;
		std::string getErrorMessage() const;
		std::size_t getSecSegOffset() const;
		std::size_t getSecSegLength() const;
		std::string getSectionName() const;
		/// @}

		/// @name Query methods
		/// @{
		bool isNamedSection() const;
		bool isMalformed() const;
		bool isEmpty() const;
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
