/**
 * @file src/fileformat/types/note_section/elf_note.cpp
 * @brief Class for ELF note segment.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/types/note_section/elf_notes.h"

namespace retdec {
namespace fileformat {


/**
 * Set type of note
 * @param type note type
 */
void ElfNote::setType(const std::size_t& type)
{
	this->type = type;
}

/**
 * Set name (owner) of note
 * @param name note name
 */
void ElfNote::setName(const std::string& name)
{
	this->name = name;
}

/**
 * Get name of note owner
 * @return owner name or empty string if name is missing
 */
std::string ElfNote::getName() const
{
	return name;
}

/**
 * Get type of note
 * @return type of note
 */
std::size_t ElfNote::getType() const
{
	return type;
}

/**
 * Check if note is system reserved empty note
 * @return @c true if note is empty, @c false otherwise
 */
bool ElfNote::isEmptyNote() const
{
	return name.empty();
}


/**
 * Ctor
 * @param assocSecSeg pointer to associated section or segment
 */
ElfNotes::ElfNotes(const SecSeg* assocSecSeg) : secSeg(assocSecSeg)
{
}

/**
 * Dtor
 */
ElfNotes::~ElfNotes()
{
}

/**
 * Add one note entry
 * @param note note entry
 */
void ElfNotes::addNote(const ElfNote& note)
{
	notes.emplace_back(note);
}

/**
 * Get notes for segment or section
 * @return vector of notes
 */
std::vector<ElfNote> ElfNotes::getNotes() const
{
	return notes;
}

/**
 * Get name of section (only sections have name)
 * @return section name or empty string if name is missing
 */
std::string ElfNotes::getSectionName() const
{
	return secSeg->getName();
}

/**
 * Get file offset of section or segment
 * @return file offset
 */
std::size_t ElfNotes::getSecSegOffset() const
{
	return secSeg->getOffset();
}

/**
 * Get length of section or segment in file
 * @return size in file
 */
std::size_t ElfNotes::getSecSegLength() const
{
	return secSeg->getSizeInFile();
}

/**
 * Check if notes belong to named section
 * @return @c true if notes belong to named section, @c false otherwise
 */
bool ElfNotes::isNamedSection() const
{
	return !secSeg->getName().empty();
}


} // namespace fileformat
} // namespace retdec
