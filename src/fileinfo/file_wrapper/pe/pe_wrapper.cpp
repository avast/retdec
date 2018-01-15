/**
 * @file src/fileinfo/file_wrapper/pe/pe_wrapper.cpp
 * @brief Methods of PeWrapper class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/array.h"
#include "retdec/utils/conversion.h"
#include "fileinfo/file_wrapper/pe/pe_wrapper.h"
#include "fileinfo/file_wrapper/pe/pe_wrapper_parser/pe_wrapper_parser32.h"
#include "fileinfo/file_wrapper/pe/pe_wrapper_parser/pe_wrapper_parser64.h"

using namespace retdec::utils;
using namespace PeLib;
using namespace retdec::fileformat;

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
std::string getSymbolLinkToSection(word link)
{
	if(!link)
	{
		return "UNDEFINED";
	}
	else if(link == std::numeric_limits<word>::max())
	{
		return "ABSOLUTE";
	}
	else if(link == std::numeric_limits<word>::max() - 1)
	{
		return "DEBUG";
	}

	return numToStr(link - 1);
}

/**
 * Get type of symbol
 * @param type Type of symbol in number representation
 * @return Type of symbol in string representation
 */
std::string getSymbolType(byte type)
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
 * @param loadFlags Load flags
 */
PeWrapper::PeWrapper(std::string pathToFile, retdec::fileformat::LoadFlags loadFlags) : PeFormat(pathToFile, loadFlags), wrapperParser(nullptr)
{
	switch(peClass)
	{
		case PEFILE32:
			wrapperParser = new PeWrapperParser32(*peHeader32);
			break;
		case PEFILE64:
			wrapperParser = new PeWrapperParser64(*peHeader64);
			break;
		default:
			stateIsValid = false;
	}
	if(stateIsValid)
	{
		file->readRelocationsDirectory();
	}
}

/**
 * Destructor
 */
PeWrapper::~PeWrapper()
{
	delete wrapperParser;
}

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
	return wrapperParser->getPeType();
}

/**
 * Get information about data directory
 * @param dirIndex Index of directory (indexed from 0)
 * @param directory Instance of class for save information about data directory
 * @return @c true if section index is valid and section is detected, @c false otherwise
 */
bool PeWrapper::getDataDirectory(unsigned long long dirIndex, DataDirectory &directory) const
{
	unsigned long long absAddr, size;
	if(!getDataDirectoryAbsolute(dirIndex, absAddr, size))
	{
		return false;
	}

	directory.setAddress(absAddr);
	directory.setSize(size);
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
	auto result = wrapperParser->getSection(secIndex, section);
	section.setCrc32("");
	section.setMd5("");
	section.setSha256("");
	unsigned long long index;
	if(strToNum(section.getIndexStr(), index))
	{
		const auto *auxSec = getSection(index);
		if(auxSec)
		{
			section.setCrc32(auxSec->getCrc32());
			section.setMd5(auxSec->getMd5());
			section.setSha256(auxSec->getSha256());
		}
	}

	return result;
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
