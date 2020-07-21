/**
 * @file src/fileinfo/file_wrapper/pe_wrapper.cpp
 * @brief Methods of PeWrapper class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/array.h"
#include "retdec/utils/conversion.h"
#include "retdec/pelib/PeFile.h"
#include "fileinfo/file_wrapper/pe_wrapper.h"

using namespace retdec::utils;
using namespace PeLib;
using namespace retdec::fileformat;

namespace retdec {
namespace fileinfo {

namespace
{

const std::string directories[] = {"Export table", "Import table", "Resource table", "Exception table",
									"Certificate Table", "Relocation table", "Debug directory",
									"Architecture directory", "Global pointer directory", "TLS Table",
									"Load configuration table", "Bound import table",
									"Import address table", "Delay import descriptor",
									"CLR runtime header", "Reserved"};

/**
 * Get type of data directory
 * @param dirIndex Directory index
 * @return Directory type of empty string if index of directory is not valid
 */
std::string getDirectoryType(unsigned long long dirIndex)
{
	return (dirIndex < arraySize(directories) ? directories[dirIndex] : "");
}

/**
 * Get link to symbol section
 * @param link Link to section in number representation
 * @return Link to section in string representation
 */
std::string getSymbolLinkToSection(std::uint16_t link)
{
	if(!link)
	{
		return "UNDEFINED";
	}
	else if(link == std::numeric_limits<std::uint16_t>::max())
	{
		return "ABSOLUTE";
	}
	else if(link == std::numeric_limits<std::uint16_t>::max() - 1)
	{
		return "DEBUG";
	}

	return std::to_string(link - 1);
}

/**
 * Get type of symbol
 * @param type Type of symbol in number representation
 * @return Type of symbol in string representation
 */
std::string getSymbolType(std::uint8_t type)
{
	if(type < 0x10)
	{
		return "SIMPLE";
	}
	else if(type < 0x20)
	{
		return "POINTER";
	}
	else if(type < 0x30)
	{
		return "FUNCTION";
	}
	else if(type < 0x40)
	{
		return "ARRAY";
	}

	return "";
}

} // anonymous namespace

/**
 * Constructor
 * @param pathToFile Path to PE binary file
 * @param dllListFile Path to text file containing list of OS DLLs
 * @param loadFlags Load flags
 */
PeWrapper::PeWrapper(
		const std::string & pathToFile,
		const std::string & dllListFile,
		retdec::fileformat::LoadFlags loadFlags)
		: PeFormat(pathToFile, dllListFile, loadFlags)
{}

/**
 * Get type of binary file
 * @return Type of binary file (e.g. DLL)
 */
std::string PeWrapper::getTypeOfFile() const
{
	return isDll() ? "DLL" : "Executable file";
}

/**
 * Get type of PE file (e.g. "PE32" or "PE32+")
 * @return Type of PE file
 */
std::string PeWrapper::getPeType() const
{
	switch(file->imageLoader().getMagic())
	{
		case PELIB_IMAGE_NT_OPTIONAL_HDR32_MAGIC:
			return "PE32";
		case PELIB_IMAGE_ROM_OPTIONAL_HDR_MAGIC:
			return "ROM image";
		case PELIB_IMAGE_NT_OPTIONAL_HDR64_MAGIC:
			return "PE32+";
		default:
			return "";
	}
}

/**
 * Get information about data directory
 * @param dirIndex Index of directory (indexed from 0)
 * @param directory Instance of class for save information about data directory
 * @return @c true if section index is valid and section is detected, @c false otherwise
 */
bool PeWrapper::getDataDirectory(unsigned long long dirIndex, DataDirectory &directory) const
{
	ImageLoader & imageLoader = file->imageLoader();
	std::uint64_t virtualAddress;

	if(dirIndex >= imageLoader.getOptionalHeader().NumberOfRvaAndSizes)
		return false;

	if((virtualAddress = imageLoader.getDataDirRva(dirIndex)) != 0)
		virtualAddress += imageLoader.getImageBase();
	directory.setAddress(virtualAddress);
	directory.setSize(imageLoader.getDataDirSize(dirIndex));
	directory.setType(getDirectoryType(dirIndex));
	return true;
}

/**
 * Get information about file section
 * @param secIndex Index of section (indexed from 0)
 * @param section Instance of class for save information about file section
 * @return @c true if section index is valid and section is detected, @c false otherwise
 */
bool PeWrapper::getFileSection(unsigned long long secIndex, FileSection &section) const
{
	const PELIB_SECTION_HEADER * pSectionHeader;
	ImageLoader & imageLoader = file->imageLoader();
	std::string sectionName;

	// Retrieve the section header. If the function returns nullptr, then there is no such section
	if((pSectionHeader = imageLoader.getSectionHeader(secIndex)) == nullptr)
		return false;

	section.setIndex(secIndex);
	section.setName(pSectionHeader->getName());
	section.setStartAddress(imageLoader.getVirtualAddressMasked(pSectionHeader->VirtualAddress));
	section.setSizeInMemory(pSectionHeader->VirtualSize);
	section.setOffset(imageLoader.getRealPointerToRawData(secIndex));
	section.setSizeInFile(pSectionHeader->SizeOfRawData);
	section.setRelocationsOffset(pSectionHeader->PointerToRelocations);
	section.setNumberOfRelocations(pSectionHeader->NumberOfRelocations);
	section.setLineNumbersOffset(pSectionHeader->PointerToLinenumbers);
	section.setNumberOfLineNumbers(pSectionHeader->NumberOfLinenumbers);
	section.setFlagsSize(0x20);
	section.setFlags(pSectionHeader->Characteristics);
	section.clearFlagsDescriptors();

	section.setCrc32("");
	section.setMd5("");
	section.setSha256("");
	unsigned long long index;

	const auto *auxSec = getSection(secIndex);
	if(auxSec)
	{
		double entropy;
		if(auxSec->getEntropy(entropy))
		{
			section.setEntropy(entropy);
		}
		section.setCrc32(auxSec->getCrc32());
		section.setMd5(auxSec->getMd5());
		section.setSha256(auxSec->getSha256());
	}

	return true;
}

/**
 * Get one symbol from COFF symbol table
 * @param index Index of symbol
 * @param symbol Instance of class for save information about symbol
 * @return @c true if symbol index is valid and symbol is detected, @c false otherwise
 */
bool PeWrapper::getCoffSymbol(unsigned long long index, Symbol &symbol) const
{
	const CoffSymbolTable &symTab = file->coffSymTab();
	if(index >= symTab.getNumberOfStoredSymbols())
	{
		return false;
	}

	symbol.setIndex(symTab.getSymbolIndex(index));
	symbol.setName(symTab.getSymbolName(index));
	symbol.setValue(symTab.getSymbolValue(index));
	symbol.setLinkToSection(getSymbolLinkToSection(symTab.getSymbolSectionNumber(index)));
	symbol.setType(getSymbolType(symTab.getSymbolTypeComplex(index)));
	return true;
}

} // namespace fileinfo
} // namespace retdec
