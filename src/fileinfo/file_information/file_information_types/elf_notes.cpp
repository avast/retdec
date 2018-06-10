/**
 * @file src/fileinfo/file_information/file_information_types/elf_notes.cpp
 * @brief ElfNotes.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_information/file_information_types/elf_notes.h"

using namespace retdec::fileformat;

namespace fileinfo {

ElfNotes::ElfNotes()
{
}

std::string ElfNotes::getSectionName() const
{
	return sectionName;
}

std::size_t ElfNotes::getSecSegOffset() const
{
	return secSegOffset;
}

std::size_t ElfNotes::getSecSegLength() const
{
	return secSegLength;
}

std::size_t ElfNotes::getNumberOfNotes() const
{
	return notes.size();
}

const std::string&ElfNotes::getErrorMessage() const
{
	return errorMessage;
}

const std::vector<ElfNoteEntry>& ElfNotes::getNotes() const
{
	return notes;
}

bool ElfNotes::isNamedSection() const
{
	return !sectionName.empty();
}

bool ElfNotes::isMalformed() const
{
	return !errorMessage.empty();
}

void ElfNotes::setSectionName(const std::string& name)
{
	sectionName = name;
}

void ElfNotes::setSecSegOffset(const std::size_t& offset)
{
	secSegOffset = offset;
}

void ElfNotes::setSecSegLength(const std::size_t& length)
{
	secSegLength = length;
}

void ElfNotes::setErrorMessage(const std::string& message)
{
	errorMessage = message;
}

void ElfNotes::addNoteEntry(const ElfNoteEntry& noteEntry)
{
	notes.emplace_back(noteEntry);
}

} // namespace fileinfo
