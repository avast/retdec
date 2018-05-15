/**
 * @file include/retdec/fileformat/file_format/pe/pe_template.h
 * @brief Template functions for PE files.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_FILE_FORMAT_PE_PE_TEMPLATE_H
#define RETDEC_FILEFORMAT_FILE_FORMAT_PE_PE_TEMPLATE_H

#include <memory>

#include "retdec/utils/range.h"
#include "retdec/utils/string.h"
#include "retdec/fileformat/file_format/pe/pe_template_aux.h"
#include "retdec/fileformat/types/dotnet_headers/clr_header.h"
#include "retdec/fileformat/types/export_table/export.h"
#include "retdec/fileformat/types/import_table/import.h"
#include "retdec/fileformat/types/import_table/pe_import.h"
#include "retdec/fileformat/types/sec_seg/pe_coff_section.h"
#include "retdec/fileformat/types/sec_seg/section.h"

namespace retdec {
namespace fileformat {

namespace
{

/**
 * Get section type
 * @param peHeader Parser of PE header
 * @param secType Parameter for store the result
 * @param sectionIndex Index of selected section (indexed from 0)
 * @return @c true if index of section is valid, @c false otherwise
 */
template<int bits> bool peSectionType(const PeLib::PeHeaderT<bits> &peHeader, PeCoffSection::Type &secType, unsigned long long sectionIndex)
{
	if(sectionIndex >= peHeader.getNumberOfSections())
	{
		return false;
	}

	std::string name;
	const unsigned long long flags = peHeader.getCharacteristics(sectionIndex);
	if(flags & PeLib::PELIB_IMAGE_SCN_CNT_CODE || flags & PeLib::PELIB_IMAGE_SCN_MEM_EXECUTE)
	{
		secType = PeCoffSection::Type::CODE;
	}
	else if(flags & PeLib::PELIB_IMAGE_SCN_CNT_UNINITIALIZED_DATA)
	{
		secType = PeCoffSection::Type::BSS;
	}
	else if(flags & PeLib::PELIB_IMAGE_SCN_MEM_DISCARDABLE && peSectionName(peHeader, name, sectionIndex) && retdec::utils::startsWith(name, ".debug_"))
	{
		secType = PeCoffSection::Type::DEBUG;
	}
	else if(flags & PeLib::PELIB_IMAGE_SCN_CNT_INITIALIZED_DATA)
	{
		secType = (!(flags & PeLib::PELIB_IMAGE_SCN_MEM_WRITE)) ? PeCoffSection::Type::CONST_DATA : PeCoffSection::Type::DATA;
	}
	else if(flags & PeLib::PELIB_IMAGE_SCN_LNK_INFO)
	{
		secType = PeCoffSection::Type::INFO;
	}
	else
	{
		secType = PeCoffSection::Type::UNDEFINED_SEC_SEG;
	}

	return true;
}

} // anonymous namespace

/**
 * Get number of sections declared in file header
 * @param peHeader Parser of PE header
 * @return Number of sections declared in file header
 */
template<int bits> unsigned long long peDeclaredNumberOfSections(const PeLib::PeHeaderT<bits> &peHeader)
{
	return peHeader.getNumberOfSections();
}

/**
 * Get number of sections actually present in the file
 * @param peHeader Parser of PE header
 * @return Stored number of sections
 */
template<int bits> unsigned long long peStoredNumberOfSections(const PeLib::PeHeaderT<bits> &peHeader)
{
	return peHeader.calcNumberOfSections();
}

/**
 * Get IMAGE_BASE virtual address
 * @param peHeader Parser of PE header
 * @return Image base virtual address
 */
template<int bits> unsigned long long peImageBase(const PeLib::PeHeaderT<bits> &peHeader)
{
	return peHeader.getImageBase();
}

/**
 * Get offset of symbol table in file
 * @param peHeader Parser of PE header
 * @return Offset of symbol table
 */
template<int bits> unsigned long long peCoffSymbolTableOffset(const PeLib::PeHeaderT<bits> &peHeader)
{
	return peHeader.getPointerToSymbolTable();
}

/**
 * Get number of symbols in symbol table
 * @param peHeader Parser of PE header
 * @return Number of symbols in symbol table
 */
template<int bits> unsigned long long peNumberOfCoffSymbols(const PeLib::PeHeaderT<bits> &peHeader)
{
	return peHeader.getNumberOfSymbols();
}

/**
 * Get major version of used linker
 * @param peHeader Parser of PE header
 * @return Major version of used linker
 */
template<int bits> unsigned long long peMajorLinkerVersion(const PeLib::PeHeaderT<bits> &peHeader)
{
	return peHeader.getMajorLinkerVersion();
}

/**
 * Get minor version of used linker
 * @param peHeader Parser of PE header
 * @return Minor version of used linker
 */
template<int bits> unsigned long long peMinorLinkerVersion(const PeLib::PeHeaderT<bits> &peHeader)
{
	return peHeader.getMinorLinkerVersion();
}

/**
 * Get file flags
 * @param peHeader Parser of PE header
 * @return File flags as one number
 */
template<int bits> unsigned long long peFileFlags(const PeLib::PeHeaderT<bits> &peHeader)
{
	return peHeader.getCharacteristics();
}

/**
 * Get time stamp
 * @param peHeader Parser of PE header
 * @return Time stamp of PE file
 */
template<int bits> unsigned long long peTimeStamp(const PeLib::PeHeaderT<bits> &peHeader)
{
	return peHeader.getTimeDateStamp();
}

/**
 * Get size of optional header
 * @param peHeader Parser of PE header
 * @return Size of optional header
 */
template<int bits> unsigned long long peSizeOfOptionalHeader(const PeLib::PeHeaderT<bits> &peHeader)
{
	return peHeader.getSizeOfOptionalHeader();
}

/**
 * Get file alignment
 * @param peHeader Parser of PE header
 * @return File alignment
 */
template<int bits> unsigned long long peFileAlignment(const PeLib::PeHeaderT<bits> &peHeader)
{
	return peHeader.getFileAlignment();
}

/**
 * Get section alignment
 * @param peHeader Parser of PE header
 * @return Section alignment
 */
template<int bits> unsigned long long peSectionAlignment(const PeLib::PeHeaderT<bits> &peHeader)
{
	return peHeader.getSectionAlignment();
}

/**
 * Get size of image
 * @param peHeader Parser of PE header
 * @return Size of image
 */
template<int bits> unsigned long long peSizeOfImage(const PeLib::PeHeaderT<bits> &peHeader)
{
	return peHeader.getSizeOfImage();
}

/**
 * Get file checksum
 * @param peHeader Parser of PE header
 * @return File checksum
 */
template<int bits> unsigned long long peChecksum(const PeLib::PeHeaderT<bits> &peHeader)
{
	return peHeader.getCheckSum();
}

/**
 * Get size of the stack to reserve
 * @param peHeader Parser of PE header
 * @return Size of the stack to reserve
 */
template<int bits> unsigned long long peSizeOfStackReserve(const PeLib::PeHeaderT<bits> &peHeader)
{
	return peHeader.getSizeOfStackReserve();
}

/**
 * Get size of the stack to commit
 * @param peHeader Parser of PE header
 * @return Size of the stack to commit
 */
template<int bits> unsigned long long peSizeOfStackCommit(const PeLib::PeHeaderT<bits> &peHeader)
{
	return peHeader.getSizeOfStackCommit();
}

/**
 * Get size of the local heap space to reserve
 * @param peHeader Parser of PE header
 * @return Size of the local heap space to reserve
 */
template<int bits> unsigned long long peSizeOfHeapReserve(const PeLib::PeHeaderT<bits> &peHeader)
{
	return peHeader.getSizeOfHeapReserve();
}

/**
 * Get size of the local heap space to commit
 * @param peHeader Parser of PE header
 * @return Size of the local heap space to commit
 */
template<int bits> unsigned long long peSizeOfHeapCommit(const PeLib::PeHeaderT<bits> &peHeader)
{
	return peHeader.getSizeOfHeapCommit();
}

/**
 * Get size of the PE signature
 * @param peHeader Parser of PE header
 * @return Size of the PE signature
 */
template<int bits> unsigned long long peSizeOfPeSignature(const PeLib::PeHeaderT<bits> &peHeader)
{
	return peHeader.getNtHeaders().sizeOfSignature();
}

/**
 * Get real loaded size of the NT headers
 * @param peHeader Parser of PE header
 * @return Real loaded size of the NT headers
 */
template<int bits> unsigned long long peLoadedSizeOfNtHeaders(const PeLib::PeHeaderT<bits> &peHeader)
{
	return peHeader.getNtHeaders().loadedSize();
}

/**
 * Get allocated size of the NT headers
 * @param peHeader Parser of PE header
 * @return Allocated size of the NT headers
 */
template<int bits> unsigned long long peAllocatedSizeOfNtHeaders(const PeLib::PeHeaderT<bits> &peHeader)
{
	return peHeader.getNtHeaders().size();
}

/**
 * Get declared number of data directories
 * @param peHeader Parser of PE header
 * @return Declared number of data directories
 */
template<int bits> unsigned long long peNumberOfDeclaredDataDirectories(const PeLib::PeHeaderT<bits> &peHeader)
{
	return peHeader.getNumberOfRvaAndSizes();
}

/**
 * Get number of stored data directories
 * @param peHeader Parser of PE header
 * @return Number of stored data directories
 */
template<int bits> unsigned long long peNumberOfStoredDataDirectories(const PeLib::PeHeaderT<bits> &peHeader)
{
	return peHeader.calcNumberOfRvaAndSizes();
}

/**
 * Get number of imported libraries
 * @param peImports Parser of PE import directory
 * @return Number of imported libraries
 */
template<int bits> unsigned long long peNumberOfImportedLibraries(const PeLib::ImportDirectory<bits> &peImports)
{
	return peImports.getNumberOfFiles(PeLib::OLDDIR);
}

/**
 * Get number of delay imported libraries
 * @param delay Parser of PE delay import directory
 * @return Number of delay imported libraries
 */
template<int bits> unsigned long long peNumberOfDelayImportedLibraries(const PeLib::DelayImportDirectory<bits> &delay)
{
	return delay.getNumberOfFiles();
}

/**
 * Get number of data directories
 * @param peHeader Parser of PE header
 * @return Number of data directories
 */
template<int bits> bool peIsDll(const PeLib::PeHeaderT<bits> &peHeader)
{
	return (peHeader.getCharacteristics() & PeLib::PELIB_IMAGE_FILE_DLL);
}

/**
 * Get virtual address of entry point
 * @param peHeader Parser of PE header
 * @return Virtual address of entry point
 */
template<int bits> unsigned long long peEpAddress(const PeLib::PeHeaderT<bits> &peHeader)
{
	return peHeader.getAddressOfEntryPoint();
}

/**
 * Get EP offset in PE binary file
 * @param peHeader Parser of PE header
 * @return Offset of entry point
 */
template<int bits> unsigned long long peEpOffset(const PeLib::PeHeaderT<bits> &peHeader)
{
	return peHeader.rvaToOffset(peHeader.getAddressOfEntryPoint());
}

/**
 * Get information about section with index @a sectionIndex
 * @param inputFile Pointer to input file
 * @param peHeader Parser of PE header
 * @param section Structure for save information about section
 * @param sectionIndex Index of section (indexed from 0)
 * @return @c true if section index is valid and section is detected, @c false otherwise
 */
template<int bits> bool peSectionWithIndex(const FileFormat *inputFile, const PeLib::PeHeaderT<bits> &peHeader, PeCoffSection &section, unsigned long long sectionIndex)
{
	std::string sectionName;
	PeCoffSection::Type sectionType;
	if(!peSectionName(peHeader, sectionName, sectionIndex) || !peSectionType(peHeader, sectionType, sectionIndex))
	{
		return false;
	}

	section.setName(sectionName);
	section.setType(sectionType);
	section.setIndex(sectionIndex);
	section.setOffset(peHeader.getPointerToRawData(sectionIndex));
	section.setSizeInFile(peHeader.getSizeOfRawData(sectionIndex));
	section.setSizeInMemory(peHeader.getVirtualSize(sectionIndex));
	section.setAddress(peHeader.getVirtualAddress(sectionIndex) ? peHeader.getVirtualAddress(sectionIndex) + peHeader.getImageBase() : 0);
	section.setMemory(section.getAddress());
	section.setPeCoffFlags(peHeader.getCharacteristics(sectionIndex));
	section.load(inputFile);
	return true;
}

/**
 * Get DLL flags
 * @param peHeader Parser of PE header
 * @param dllFlags Into this parameter DLL flags will be stored
 * @return @c true if file is DLL and flags are successfully detected, @c false otherwise
 *
 * If file is not DLL, @a dllFlags is left unchanged
 */
template<int bits> bool peDllFlags(const PeLib::PeHeaderT<bits> &peHeader, unsigned long long &dllFlags)
{
	if(peHeader.getCharacteristics() & PeLib::PELIB_IMAGE_FILE_DLL)
	{
		dllFlags = peHeader.getDllCharacteristics();
		return true;
	}

	return false;
}

/**
 * Get information about data directory
 * @param peHeader Parser of PE header
 * @param relAddr Into this parameter is stored relative virtual address of directory
 * @param size Into this parameter is stored size of directory
 * @param index Index of selected directory
 * @return @c true if index of selected directory is valid, @c false otherwise
 *
 * If method returns @c false, @a relAddr and @a size are left unchanged.
 */
template<int bits> bool peDataDirectoryRelative(const PeLib::PeHeaderT<bits> &peHeader, unsigned long long &relAddr, unsigned long long &size, unsigned long long index)
{
	if(index >= peNumberOfStoredDataDirectories(peHeader))
	{
		return false;
	}

	relAddr = peHeader.getImageDataDirectoryRva(index);
	size = peHeader.getImageDataDirectorySize(index);
	return true;
}

/**
 * Get information about data directory
 * @param peHeader Parser of PE header
 * @param absAddr Into this parameter is stored absolute virtual address of directory
 * @param size Into this parameter is stored size of directory
 * @param index Index of selected directory
 * @return @c true if index of selected directory is valid, @c false otherwise
 *
 * If directory start address is non-zero, start address of directory will be
 * set to "image base + relative virtual address". Otherwise, address will be
 * set to zero.
 *
 * If function returns @c false, @a absAddr and @a size are left unchanged.
 */
template<int bits> bool peDataDirectoryAbsolute(const PeLib::PeHeaderT<bits> &peHeader, unsigned long long &absAddr, unsigned long long &size, unsigned long long index)
{
	if(index >= peNumberOfStoredDataDirectories(peHeader))
	{
		return false;
	}

	absAddr = peHeader.getImageDataDirectoryRva(index);
	if(absAddr)
	{
		absAddr += peHeader.getImageBase();
	}
	size = peHeader.getImageDataDirectorySize(index);
	return true;
}

/**
 * Get name of imported library
 * @param peImports Parser of PE import directory
 * @param fileName Into this parameter is stored name of imported library
 * @param index Index of selected library (indexed from 0)
 * @return @c true if index of selected library is valid, @c false otherwise
 *
 * If function returns @c false, @a fileName is left unchanged.
 */
template<int bits> bool peImportedLibraryFileName(const PeLib::ImportDirectory<bits> &peImports, std::string &fileName, unsigned long long index)
{
	if(index >= peNumberOfImportedLibraries(peImports))
	{
		return false;
	}

	fileName = peImports.getFileName(index, PeLib::OLDDIR);
	return true;
}

/**
 * Get name of delay imported library
 * @param delay Parser of PE delay import directory
 * @param fileName Into this parameter is stored name of delay imported library
 * @param index Index of selected library (indexed from 0)
 * @return @c true if index of selected library is valid, @c false otherwise
 *
 * If function returns @c false, @a fileName is left unchanged.
 */
template<int bits> bool peDelayImportedLibraryFileName(const PeLib::DelayImportDirectory<bits> &delay, std::string &fileName, unsigned long long index)
{
	const auto *library = delay.getFile(index);
	if(!library)
	{
		return false;
	}

	fileName = library->Name;

	return true;
}

/**
 * Get information about import
 * @param peHeader Parser of PE header
 * @param peImports Parser of PE import directory
 * @param fileIndex Index of selected library (indexed from 0)
 * @param importIndex Index of selected import (indexed from 0)
 * @return @c true if index of library and index of import are valid, @c false otherwise
 *
 * If function returns info about import, or @c nullptr if invalid import is requested.
 */
template<int bits> std::unique_ptr<PeImport> peImport(const PeLib::PeHeaderT<bits> &peHeader,
	const PeLib::ImportDirectory<bits> &peImports,
	unsigned long long fileIndex, unsigned long long importIndex)
{
	if(fileIndex >= peNumberOfImportedLibraries(peImports) ||
		importIndex >= peImports.getNumberOfFunctions(fileIndex, PeLib::OLDDIR))
	{
		return nullptr;
	}

	auto isOrdinalNumberValid = true;
	unsigned long long ordinalNumber = peImports.getFunctionHint(fileIndex, importIndex, PeLib::OLDDIR);
	if(!ordinalNumber)
	{
		const auto firstThunk = peImports.getFirstThunk(fileIndex, importIndex, PeLib::OLDDIR);
		const auto originalFirstThunk = peImports.getOriginalFirstThunk(fileIndex, importIndex, PeLib::OLDDIR);
		if(firstThunk & PeLib::PELIB_IMAGE_ORDINAL_FLAGS<bits>::PELIB_IMAGE_ORDINAL_FLAG)
		{
			ordinalNumber = firstThunk - PeLib::PELIB_IMAGE_ORDINAL_FLAGS<bits>::PELIB_IMAGE_ORDINAL_FLAG;
		}
		else if(originalFirstThunk & PeLib::PELIB_IMAGE_ORDINAL_FLAGS<bits>::PELIB_IMAGE_ORDINAL_FLAG)
		{
			ordinalNumber = originalFirstThunk - PeLib::PELIB_IMAGE_ORDINAL_FLAGS<bits>::PELIB_IMAGE_ORDINAL_FLAG;
		}
		else
		{
			isOrdinalNumberValid = false;
		}
	}

	auto import = std::make_unique<PeImport>(PeImportFlag::None);
	if(isOrdinalNumberValid)
	{
		import->setOrdinalNumber(ordinalNumber);
	}
	else
	{
		import->invalidateOrdinalNumber();
	}
	import->setName(peImports.getFunctionName(fileIndex, importIndex, PeLib::OLDDIR));
	import->setAddress(peImageBase(peHeader) + peImports.getFirstThunk(fileIndex, PeLib::OLDDIR) + importIndex * (bits / 8));
	import->setLibraryIndex(fileIndex);
	return import;
}

/**
 * Get information about delay import
 * @param peHeader Parser of PE header
 * @param delay Parser of PE delay import directory
 * @param fileIndex Index of selected library (indexed from 0)
 * @param importIndex Index of selected delay import (indexed from 0)
 * @return @c true if index of library and index of delay import are valid, @c false otherwise
 *
 * If function returns info about delayed import, or @c nullptr if invalid import is requested.
 */
template<int bits> std::unique_ptr<PeImport> peDelayImport(const PeLib::PeHeaderT<bits> &peHeader,
	const PeLib::DelayImportDirectory<bits> &delay,
	unsigned long long fileIndex, unsigned long long importIndex)
{
	const auto *library = delay.getFile(fileIndex);
	if(!library)
	{
		return nullptr;
	}

	const auto *function = library->getFunction(importIndex);
	if(!function)
	{
		return nullptr;
	}

	auto import = std::make_unique<PeImport>(PeImportFlag::Delayed);
	import->setName(function->fname);
	import->setAddress(peImageBase(peHeader) + function->address.Value);
	import->setLibraryIndex(fileIndex);
	import->invalidateOrdinalNumber();
	if(library->ordinalNumbersAreValid() && function->hint != 0)
	{
		import->setOrdinalNumber(function->hint);
	}

	return import;
}

/**
 * Get number of exported functions
 * @param exports Parser of PE export directory
 * @return Number of exported functions
 */
template<int bits> unsigned long long peNumberOfExportedFunctions(const PeLib::ExportDirectoryT<bits> &exports)
{
	return exports.calcNumberOfFunctions();
}

/**
 * Get information about the exported function
 * @param peHeader Parser of PE header
 * @param exports Parser of PE export directory
 * @param index Index of the exported function
 * @param exportedFunction Exported function to fill
 * @return @c false if index is out of bounds, otherwise @c true
 */
template<int bits> bool peExportedFunction(const PeLib::PeHeaderT<bits> &peHeader, const PeLib::ExportDirectoryT<bits> &exports, unsigned long long index, Export& exportedFunction)
{
	if (index >= peNumberOfExportedFunctions(exports))
	{
		return false;
	}

	exportedFunction.setAddress(exports.getAddressOfFunction(index) + peImageBase(peHeader));
	exportedFunction.setOrdinalNumber(exports.getFunctionOrdinal(index));
	exportedFunction.setName(exports.getFunctionName(index));
	return true;
}

/**
 * Get number of debug entries
 * @param debug Parser of PE debug directory
 * @return Number of debug entries
 */
template<int bits> unsigned long long peNumberOfDebugEntries(const PeLib::DebugDirectoryT<bits> &debug)
{
	return debug.calcNumberOfEntries();
}

/**
 * Get debug entry data
 * @param debug Parser of PE debug directory
 * @param index Index of debug entry
 * @param data Data to fill
 * @return @c false if index is out of bounds, otherwise @c true
 */
template<int bits> bool peDebugEntryData(const PeLib::DebugDirectoryT<bits> &debug, unsigned long long index, std::vector<std::uint8_t>& data)
{
	if (index >= peNumberOfDebugEntries(debug))
	{
		return false;
	}

	data = debug.getData(index);
	return true;
}

/**
 * Get debug entry timestamp
 * @param debug Parser of PE debug directory
 * @param index Index of debug entry
 * @param timeDateStamp Timestamp to fill
 * @return @c false if index is out of bounds, otherwise @c true
 */
template<int bits> bool peDebugEntryTimeDateStamp(const PeLib::DebugDirectoryT<bits> &debug, unsigned long long index, unsigned long long& timeDateStamp)
{
	if (index >= peNumberOfDebugEntries(debug))
	{
		return false;
	}

	timeDateStamp = debug.getTimeDateStamp(index);
	return true;
}

/**
 * Get debug entry pointer to raw data
 * @param debug Parser of PE debug directory
 * @param index Index of debug entry
 * @param pointerToRawData Pointer to raw data to fill
 * @return @c false if index is out of bounds, otherwise @c true
 */
template<int bits> bool peDebugEntryPointerToRawData(const PeLib::DebugDirectoryT<bits> &debug, unsigned long long index, unsigned long long& pointerToRawData)
{
	if (index >= peNumberOfDebugEntries(debug))
	{
		return false;
	}

	pointerToRawData = debug.getPointerToRawData(index);
	return true;
}

/**
 * Get resource directory file offset
 * @param resources Parser of PE resource directory
 * @return Directory file offset
 */
template<int bits> unsigned long long peResourceDirectoryOffset(const PeLib::ResourceDirectoryT<bits> &resources)
{
	return resources.getOffset();
}

/**
 * Get resource directory tree root node
 * @param resources Parser of PE resource directory
 * @return Directory tree root node
 */
template<int bits> const PeLib::ResourceNode* peResourceTreeRoot(const PeLib::ResourceDirectoryT<bits> &resources)
{
	return resources.getRoot();
}

/**
 * Get CLR header
 * @param comHeader Parser of PE COM/CLR directory
 * @return Parsed CLR header
 */
template<int bits> std::unique_ptr<CLRHeader> peGetClrHeader(const PeLib::ComHeaderDirectoryT<bits> &comHeader)
{
	auto clrHeader = std::make_unique<CLRHeader>();
	clrHeader->setHeaderSize(comHeader.getSizeOfHeader());
	clrHeader->setMajorRuntimeVersion(comHeader.getMajorRuntimeVersion());
	clrHeader->setMinorRuntimeVersion(comHeader.getMinorRuntimeVersion());
	clrHeader->setMetadataDirectoryAddress(comHeader.getMetaDataVa());
	clrHeader->setMetadataDirectorySize(comHeader.getMetaDataSize());
	clrHeader->setFlags(comHeader.getFlags());
	clrHeader->setEntryPointToken(comHeader.getEntryPointToken());
	clrHeader->setResourcesAddress(comHeader.getResourcesVa());
	clrHeader->setResourcesSize(comHeader.getResourcesSize());
	clrHeader->setStrongNameSignatureAddress(comHeader.getStrongNameSignatureVa());
	clrHeader->setStrongNameSignatureSize(comHeader.getStrongNameSignatureSize());
	clrHeader->setCodeManagerTableAddress(comHeader.getCodeManagerTableVa());
	clrHeader->setCodeManagerTableSize(comHeader.getCodeManagerTableSize());
	clrHeader->setVTableFixupsDirectoryAddress(comHeader.getVTableFixupsVa());
	clrHeader->setVTableFixupsDirectorySize(comHeader.getVTableFixupsSize());
	clrHeader->setExportAddressTableAddress(comHeader.getExportAddressTableJumpsVa());
	clrHeader->setExportAddressTableSize(comHeader.getExportAddressTableJumpsSize());
	clrHeader->setPrecompileHeaderAddress(comHeader.getManagedNativeHeaderVa());
	clrHeader->setPrecompileHeaderSize(comHeader.getManagedNativeHeaderSize());
	return clrHeader;
}

/**
 * Get number of relocations
 * @param relocs Parser of PE relocation directory
 * @return Number of relocations
 */
template<int bits> unsigned long long peNumberOfRelocations(const PeLib::RelocationsDirectoryT<bits> &relocs)
{
	return relocs.calcNumberOfRelocations();
}

/**
 * Get number of relocation data
 * @param relocs Parser of PE relocation directory
 * @param index Relocation data index
 * @return Number of relocation data
 */
template<int bits> unsigned long long peNumberOfRelocationData(const PeLib::RelocationsDirectoryT<bits> &relocs, unsigned long long index)
{
	return relocs.calcNumberOfRelocationData(index);
}

/**
 * Get file offset of checksum field in PE header
 * @param peHeader Parser of PE header
 * @return File offset of checksum
 */
template<int bits> unsigned long long peChecksumFileOffset(const PeLib::PeHeaderT<bits> &peHeader)
{
	return peHeader.getChecksumFileOffset();
}

/**
 * Get file offset of security data directory in PE header
 * @param peHeader Parser of PE header
 * @return File offset of security data directory
 */
template<int bits> unsigned long long peSecurityDirFileOffset(const PeLib::PeHeaderT<bits> &peHeader)
{
	return peHeader.getSecDirFileOffset();
}

/**
 * Get RVA of security directory
 * @param peHeader Parser of PE header
 * @return RVA of security directory
 */
template<int bits> unsigned long long peSecurityDirRva(const PeLib::PeHeaderT<bits> &peHeader)
{
	return peHeader.getIddSecurityRva();
}

/**
 * Get size of security directory
 * @param peHeader Parser of PE header
 * @return Size of security directory
 */
template<int bits> unsigned long long peSecurityDirSize(const PeLib::PeHeaderT<bits> &peHeader)
{
	return peHeader.getIddSecuritySize();
}

/**
 * Get occupied addresses by import directory
 * @param peImports Parser of PE import directory
 * @return Occupied address ranges
 */
template<int bits> retdec::utils::RangeContainer<std::uint64_t> peImportDirectoryOccupiedAddresses(const PeLib::ImportDirectory<bits> &peImports)
{
	retdec::utils::RangeContainer<std::uint64_t> result;
	for (const auto& addresses : peImports.getOccupiedAddresses())
	{
		try
		{
			result.addRange(retdec::utils::Range<std::uint64_t>{addresses.first, addresses.second});
		}
		catch (const retdec::utils::InvalidRangeException&)
		{
			continue;
		}
	}

	return result;
}

/**
 * Get occupied addresses by export directory
 * @param peExports Parser of PE export directory
 * @return Occupied address ranges
 */
template<int bits> retdec::utils::RangeContainer<std::uint64_t> peExportDirectoryOccupiedAddresses(const PeLib::ExportDirectoryT<bits> &peExports)
{
	retdec::utils::RangeContainer<std::uint64_t> result;
	for (const auto& addresses : peExports.getOccupiedAddresses())
	{
		try
		{
			result.addRange(retdec::utils::Range<std::uint64_t>{addresses.first, addresses.second});
		}
		catch (const retdec::utils::InvalidRangeException&)
		{
			continue;
		}
	}

	return result;
}

/**
 * Get occupied addresses by debug directory
 * @param peDebug Parser of PE debug directory
 * @return Occupied address ranges
 */
template<int bits> retdec::utils::RangeContainer<std::uint64_t> peDebugDirectoryOccupiedAddresses(const PeLib::DebugDirectoryT<bits> &peDebug)
{
	retdec::utils::RangeContainer<std::uint64_t> result;
	for (const auto& addresses : peDebug.getOccupiedAddresses())
	{
		try
		{
			result.addRange(retdec::utils::Range<std::uint64_t>{addresses.first, addresses.second});
		}
		catch (const retdec::utils::InvalidRangeException&)
		{
			continue;
		}
	}

	return result;
}

/**
 * Get occupied addresses by resource directory
 * @param peResources Parser of PE resource directory
 * @return Occupied address ranges
 */
template<int bits> retdec::utils::RangeContainer<std::uint64_t> peResourceDirectoryOccupiedAddresses(const PeLib::ResourceDirectoryT<bits> &peResources)
{
	retdec::utils::RangeContainer<std::uint64_t> result;
	for (const auto& addresses : peResources.getOccupiedAddresses())
	{
		try
		{
			result.addRange(retdec::utils::Range<std::uint64_t>{addresses.first, addresses.second});
		}
		catch (const retdec::utils::InvalidRangeException&)
		{
			continue;
		}
	}

	return result;
}

} // namespace fileformat
} // namespace retdec

#endif
