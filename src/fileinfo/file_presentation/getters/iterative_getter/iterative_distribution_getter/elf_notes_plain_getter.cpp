/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/elf_notes_plain_getter.cpp
 * @brief Methods of ElfNotesPlainGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_presentation/getters/iterative_getter/iterative_distribution_getter/elf_notes_plain_getter.h"
#include "retdec/utils/conversion.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace fileinfo {

namespace
{

const std::size_t headerDistArr[] = {5, 12, 14, 14, 8, 30};

const std::string headerNameArr[] = {
	"i", "owner", "type", "offset", "size", "description"
};

const std::string headerDescArr[] = {
	"index", "note owner", "note type", "note data file offset",
	"note data size in file", "text description"
};

} // anonymous namespace

/**
 * Constructor
 * @param fileInfo Information about file
 */
ElfNotesPlainGetter::ElfNotesPlainGetter(
		FileInformation &fileInfo)
	: IterativeDistributionGetter(fileInfo)
{
	auto& notes = fileinfo.getElfNotes();

	numberOfStructures = notes.size();
	for(std::size_t i = 0; i < numberOfStructures; ++i)
	{
		numberOfStoredRecords.push_back(notes[i].getNumberOfNotes());
		numberOfExtraElements.push_back(0);
	}

	title = "Notes";
	distribution.insert(
				distribution.begin(),
				std::begin(headerDistArr),
				std::end(headerDistArr));
	commonHeaderElements.insert(
				commonHeaderElements.begin(),
				std::begin(headerNameArr),
				std::end(headerNameArr));
	commonHeaderDesc.insert(
				commonHeaderDesc.begin(),
				std::begin(headerDescArr),
				std::end(headerDescArr));
	loadRecords();
}

/**
 * Destructor
 */
ElfNotesPlainGetter::~ElfNotesPlainGetter()
{
}

std::size_t ElfNotesPlainGetter::getBasicInfo(
		std::size_t structIndex,
		std::vector<std::string> &desc,
		std::vector<std::string> &info) const
{
	if(structIndex >= numberOfStructures)
	{
		return 0;
	}

	desc.clear();
	info.clear();

	auto notes = fileinfo.getElfNotes()[structIndex];
	if(notes.isNamedSection())
	{
		desc.push_back("Name           : ");
		info.push_back(replaceNonprintableChars(notes.getSectionName()));
	}
	if(notes.isMalformed())
	{
		desc.push_back("Warning        : ");
		info.push_back(notes.getErrorMessage());
	}
	desc.push_back("File offset    : ");
	desc.push_back("Size in file   : ");
	desc.push_back("Number of notes: ");
	info.push_back(toHex(notes.getSecSegOffset(), true));
	info.push_back(numToStr(notes.getSecSegLength()));
	info.push_back(numToStr(notes.getNotes().size()));

	return info.size();
}

bool ElfNotesPlainGetter::loadRecord(
		std::size_t structIndex,
		std::size_t recIndex,
		std::vector<std::string> &record)
{
	if(structIndex >= numberOfStructures
			|| recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	const auto& notes = fileinfo.getElfNotes()[structIndex];
	const auto& note = notes.getNotes()[recIndex];

	record.clear();
	record.push_back(numToStr(recIndex));
	record.push_back(replaceNonprintableChars(note.owner));
	record.push_back(toHex(note.type, true, 8));
	record.push_back(toHex(note.dataOffset, true, 8));
	record.push_back(numToStr(note.dataLength));
	record.push_back(replaceNonprintableChars(note.description));

	return true;
}

bool ElfNotesPlainGetter::getFlagDescriptors(
		std::size_t structIndex, std::vector<std::string> &desc,
		std::vector<std::string> &abbv) const
{
	if(structIndex >= numberOfStructures)
	{
		return false;
	}

	desc.clear();
	abbv.clear();

	return true;
}

} // namespace fileinfo
