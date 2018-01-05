/**
 * @file src/fileinfo/file_wrapper/elf_wrapper.cpp
 * @brief Methods of ElfWrapper class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_wrapper/elf_wrapper.h"

using namespace ELFIO;

namespace fileinfo {

/**
 * Constructor
 * @param pathToFile Path to ELF binary file
 * @param loadFlags Load flags
 */
ElfWrapper::ElfWrapper(std::string pathToFile, retdec::fileformat::LoadFlags loadFlags) : ElfFormat(pathToFile, loadFlags)
{

}

/**
 * Destructor
 */
ElfWrapper::~ElfWrapper()
{

}

/**
 * Get file segment
 * @param segIndex Index of required segment (indexed from 0)
 * @return Pointer to segment or @c nullptr if any error
 *
 * If @a segIndex is out of range, method will return @c nullptr
 */
ELFIO::segment* ElfWrapper::getFileSegment(unsigned long long segIndex) const
{
	return segIndex < reader.segments.size() ? reader.segments[segIndex] : nullptr;
}

/**
 * Get file section
 * @param secIndex Index of required section (indexed from 0)
 * @return Pointer to section or @c nullptr if any error
 *
 * If @a secIndex is out of range, method will return @c nullptr
 */
ELFIO::section* ElfWrapper::getFileSection(unsigned long long secIndex) const
{
	return secIndex < reader.sections.size() ? reader.sections[secIndex] : nullptr;
}

/**
 * Get symbol table
 * @param secIndex Index of section which is symbol table (indexed from 0)
 * @return Pointer to symbol table or @c nullptr if any error
 *
 * If required section is not symbol table, method will return @c nullptr
 *
 * Pointer to symbol table accessor is dynamically allocated and must be released
 *    (otherwise there is a memory leak)
 */
ELFIO::symbol_section_accessor* ElfWrapper::getSymbolTable(unsigned long long secIndex) const
{
	section *fileSec = getFileSection(secIndex);
	if(!fileSec)
	{
		return nullptr;
	}

	const unsigned long long secType = fileSec->get_type();
	return (secType == SHT_SYMTAB || secType == SHT_DYNSYM) ?
			new symbol_section_accessor(reader, fileSec) : nullptr;
}

/**
 * Get relocation table
 * @param secIndex Index of section which is relocation table (indexed from 0)
 * @return Pointer to relocation table or @c nullptr if any error
 *
 * If required section is not relocation table, method will return @c nullptr
 *
 * Pointer to relocation table accessor is dynamically allocated and must be released
 *    (otherwise there is a memory leak)
 */
ELFIO::relocation_section_accessor* ElfWrapper::getRelocationTable(unsigned long long secIndex) const
{
	section *fileSec = getFileSection(secIndex);
	if(!fileSec)
	{
		return nullptr;
	}

	const unsigned long long secType = fileSec->get_type();
	return (secType == SHT_RELA || secType == SHT_REL) ?
			new relocation_section_accessor(reader, fileSec) : nullptr;
}

/**
 * Get dynamic section
 * @param secIndex Index of dynamic section (indexed from 0)
 * @return Pointer to dynamic section or @c nullptr if any error
 *
 * If required section is not dynamic section, method will return @c nullptr
 *
 * Pointer to dynamic section accessor is dynamically allocated and must be released
 *    (otherwise there is a memory leak)
 */
ELFIO::dynamic_section_accessor* ElfWrapper::getDynamicSection(unsigned long long secIndex) const
{
	section *fileSec = getFileSection(secIndex);
	if(!fileSec)
	{
		return nullptr;
	}

	const unsigned long long secType = fileSec->get_type();
	return secType == SHT_DYNAMIC ? new dynamic_section_accessor(reader, fileSec) : nullptr;
}

} // namespace fileinfo
