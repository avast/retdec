/**
 * @file include/retdec/fileformat/types/note_section/elf_note.cpp
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
class ElfNote
{
	public:
		std::string name; ///< interpreted name (owner)
		std::size_t type; ///< owner specific type

		// Type must be combined with name to tell how to interpret data

		std::size_t dataOffset; ///< file offset of data
		std::size_t dataLength; ///< length of note

		/// Query methods
		/// @{
		bool isEmptyNote() const;
		/// @}
};

/**
 * Class describing one ELF note section or segment
 */
class ElfNotes
{
	private:
		const SecSeg* secSeg;       ///< associated section or segment
		std::vector<ElfNote> notes; ///< notes in segment or section

	public:
		/// Constructors and destructor
		/// @{
		ElfNotes(const SecSeg* assocSecSeg);
		~ElfNotes();
		/// @}

		/// Add notes
		/// @{
		void addNote(ElfNote&& note);
		void addNote(const ElfNote& note);
		/// @}

		/// Getters
		/// @{
		std::vector<ElfNote> getNotes() const;
		std::size_t getSecSegOffset() const;
		std::size_t getSecSegLength() const;
		std::string getSectionName() const;
		/// @}

		/// Query methods
		/// @{
		bool isNamedSection() const;
		bool isEmpty() const;
		/// @}
};



} // namespace fileformat
} // namespace retdec

#endif
