/**
 * @file src/fileformat/types/note_section/elf_notes.cpp
 * @brief Class for ELF note segment.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/types/note_section/elf_notes.h"

namespace retdec {
namespace fileformat {

/**
 * Check if note is system reserved empty note
 * @return @c true if note is empty, @c false otherwise
 */
bool ElfNoteEntry::isEmptyNote() const
{
	return name.empty();
}

/**
 * Constructor
 * @param assocSecSeg pointer to associated section or segment
 */
ElfNoteSecSeg::ElfNoteSecSeg(const SecSeg* assocSecSeg) : secSeg(assocSecSeg)
{
}

/**
 * Destructor
 */
ElfNoteSecSeg::~ElfNoteSecSeg()
{
}

/**
 * Set malformed bit for notes
 * @param message optional error message
 */
void ElfNoteSecSeg::setMalformed(const std::string& message)
{
	malformed = true;
	error = "malformed - " + message;
}

/**
 * Add one note entry (move)
 * @param note note entry
 */
void ElfNoteSecSeg::addNote(ElfNoteEntry&& note)
{
	notes.emplace_back(std::move(note));
}

/**
 * Add one note entry (copy)
 * @param note note entry
 */
void ElfNoteSecSeg::addNote(const ElfNoteEntry& note)
{
	notes.emplace_back(note);
}

/**
 * Get notes for segment or section
 * @return vector of notes
 */
std::vector<ElfNoteEntry> ElfNoteSecSeg::getNotes() const
{
	return notes;
}

/**
 * Get error message for malformed binaries
 * @return error message or empty string if notes are not malformed
 */
std::string ElfNoteSecSeg::getErrorMessage() const
{
	return error;
}

/**
 * Get file offset of section or segment
 * @return file offset
 */
std::size_t ElfNoteSecSeg::getSecSegOffset() const
{
	return secSeg->getOffset();
}

/**
 * Get length of section or segment in file
 * @return size in file
 */
std::size_t ElfNoteSecSeg::getSecSegLength() const
{
	return secSeg->getSizeInFile();
}

/**
 * Get name of section (only sections have name)
 * @return section name or empty string if name is missing
 */
std::string ElfNoteSecSeg::getSectionName() const
{
	return secSeg->getName();
}

/**
 * Check if notes belong to named section
 * @return @c true if notes belong to named section, @c false otherwise
 */
bool ElfNoteSecSeg::isNamedSection() const
{
	return !secSeg->getName().empty();
}

/**
 * Check if notes are malformed
 * @return @c true if notes are malformed, @c false otherwise
 */
bool ElfNoteSecSeg::isMalformed() const
{
	return malformed;
}

/**
 * Check if object contains any notes
 * @return @c true if object contains any notes, @c false otherwise
 */
bool ElfNoteSecSeg::isEmpty() const
{
	return notes.empty();
}

} // namespace fileformat
} // namespace retdec
