/**
 * @file src/fileformat/file_format/pe/pe_format_parser/pe_format_parser32.cpp
 * @brief Methods of PeFormatParser32 class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/file_format/file_format.h"
#include "retdec/fileformat/file_format/pe/pe_format_parser/pe_format_parser32.h"
#include "retdec/fileformat/file_format/pe/pe_template.h"

using namespace PeLib;

namespace retdec {
namespace fileformat {

/**
 * Constructor
 * @param fInputFile Pointer to input file
 * @param peFile32 32-bit PE file
 */
PeFormatParser32::PeFormatParser32(const FileFormat *fInputFile, PeLib::PeFileT<32> *peFile32) : PeFormatParser(fInputFile),
	peFile(peFile32), peHeader(peFile32->peHeader())
{

}

/**
 * Destructor
 */
PeFormatParser32::~PeFormatParser32()
{

}

unsigned long long PeFormatParser32::getDeclaredNumberOfSections() const
{
	return peDeclaredNumberOfSections(peHeader);
}

unsigned long long PeFormatParser32::getStoredNumberOfSections() const
{
	return peStoredNumberOfSections(peHeader);
}

unsigned long long PeFormatParser32::getMachineType() const
{
	return peHeader.getMachine();
}

unsigned long long PeFormatParser32::getImageBaseAddress() const
{
	return peImageBase(peHeader);
}

unsigned long long PeFormatParser32::getCoffSymbolTableOffset() const
{
	return peCoffSymbolTableOffset(peHeader);
}

unsigned long long PeFormatParser32::getNumberOfCoffSymbols() const
{
	return peNumberOfCoffSymbols(peHeader);
}

unsigned long long PeFormatParser32::getMajorLinkerVersion() const
{
	return peMajorLinkerVersion(peHeader);
}

unsigned long long PeFormatParser32::getMinorLinkerVersion() const
{
	return peMinorLinkerVersion(peHeader);
}

unsigned long long PeFormatParser32::getFileFlags() const
{
	return peFileFlags(peHeader);
}

unsigned long long PeFormatParser32::getTimeStamp() const
{
	return peTimeStamp(peHeader);
}

unsigned long long PeFormatParser32::getOptionalHeaderSize() const
{
	return peSizeOfOptionalHeader(peHeader);
}

unsigned long long PeFormatParser32::getFileAlignment() const
{
	return peFileAlignment(peHeader);
}

unsigned long long PeFormatParser32::getSectionAlignment() const
{
	return peSectionAlignment(peHeader);
}

unsigned long long PeFormatParser32::getSizeOfImage() const
{
	return peSizeOfImage(peHeader);
}

unsigned long long PeFormatParser32::getChecksum() const
{
	return peChecksum(peHeader);
}

unsigned long long PeFormatParser32::getSizeOfStackReserve() const
{
	return peSizeOfStackReserve(peHeader);
}

unsigned long long PeFormatParser32::getSizeOfStackCommit() const
{
	return peSizeOfStackCommit(peHeader);
}

unsigned long long PeFormatParser32::getSizeOfHeapReserve() const
{
	return peSizeOfHeapReserve(peHeader);
}

unsigned long long PeFormatParser32::getSizeOfHeapCommit() const
{
	return peSizeOfHeapCommit(peHeader);
}

unsigned long long PeFormatParser32::getSizeOfPeSignature() const
{
	return peSizeOfPeSignature(peHeader);
}

unsigned long long PeFormatParser32::getLoadedSizeOfNtHeaders() const
{
	return peLoadedSizeOfNtHeaders(peHeader);
}

unsigned long long PeFormatParser32::getAllocatedSizeOfNtHeaders() const
{
	return peAllocatedSizeOfNtHeaders(peHeader);
}

unsigned long long PeFormatParser32::getDeclaredNumberOfDataDirectories() const
{
	return peNumberOfDeclaredDataDirectories(peHeader);
}

unsigned long long PeFormatParser32::getStoredNumberOfDataDirectories() const
{
	return peNumberOfStoredDataDirectories(peHeader);
}

unsigned long long PeFormatParser32::getNumberOfImportedLibraries() const
{
	return peNumberOfImportedLibraries(peFile->impDir());
}

unsigned long long PeFormatParser32::getNumberOfDelayImportedLibraries() const
{
	return peNumberOfDelayImportedLibraries(peFile->delayImports());
}

bool PeFormatParser32::isDll() const
{
	return peIsDll(peHeader);
}

bool PeFormatParser32::getEpAddress(unsigned long long &epAddress) const
{
	const auto addr = peEpAddress(peHeader);
	// file has no entry point
	if(!addr && !peEpOffset(peHeader))
	{
		return false;
	}

	epAddress = addr + peImageBase(peHeader);
	return true;
}

bool PeFormatParser32::getEpOffset(unsigned long long &epOffset) const
{
	unsigned long long epAddress = 0;
	if(!getEpAddress(epAddress))
	{
		return false;
	}

	const auto offset = peEpOffset(peHeader);
	if(offset == std::numeric_limits<dword>::max())
	{
		return false;
	}

	epOffset = offset;
	return true;
}

bool PeFormatParser32::getSection(unsigned long long secIndex, PeCoffSection &section) const
{
	return peSectionWithIndex(inputFile, peHeader, section, secIndex);
}

bool PeFormatParser32::getDllFlags(unsigned long long &dllFlags) const
{
	return peDllFlags(peHeader, dllFlags);
}

bool PeFormatParser32::getDataDirectoryRelative(unsigned long long index, unsigned long long &relAddr, unsigned long long &size) const
{
	return peDataDirectoryRelative(peHeader, relAddr, size, index);
}

bool PeFormatParser32::getDataDirectoryAbsolute(unsigned long long index, unsigned long long &absAddr, unsigned long long &size) const
{
	return peDataDirectoryAbsolute(peHeader, absAddr, size, index);
}

bool PeFormatParser32::getImportedLibraryFileName(unsigned long long index, std::string &fileName) const
{
	return peImportedLibraryFileName(peFile->impDir(), fileName, index);
}

bool PeFormatParser32::getDelayImportedLibraryFileName(unsigned long long index, std::string &fileName) const
{
	return peDelayImportedLibraryFileName(peFile->delayImports(), fileName, index);
}

std::unique_ptr<PeImport> PeFormatParser32::getImport(unsigned long long fileIndex, unsigned long long importIndex) const
{
	return peImport(peHeader, peFile->impDir(), fileIndex, importIndex);
}

std::unique_ptr<PeImport> PeFormatParser32::getDelayImport(unsigned long long fileIndex, unsigned long long importIndex) const
{
	return peDelayImport(peHeader, peFile->delayImports(), fileIndex, importIndex);
}

unsigned long long PeFormatParser32::getNumberOfExportedFunctions() const
{
	return peNumberOfExportedFunctions(peFile->expDir());
}

bool PeFormatParser32::getExportedFunction(unsigned long long index, Export& exportedFunction) const
{
	return peExportedFunction(peHeader, peFile->expDir(), index, exportedFunction);
}

unsigned long long PeFormatParser32::getNumberOfDebugEntries() const
{
	return peNumberOfDebugEntries(peFile->debugDir());
}

bool PeFormatParser32::getDebugEntryData(unsigned long long index, std::vector<std::uint8_t>& data) const
{
	return peDebugEntryData(peFile->debugDir(), index, data);
}

bool PeFormatParser32::getDebugEntryTimeDateStamp(unsigned long long index, unsigned long long& timeDateStamp) const
{
	return peDebugEntryTimeDateStamp(peFile->debugDir(), index, timeDateStamp);
}

bool PeFormatParser32::getDebugEntryPointerToRawData(unsigned long long index, unsigned long long& pointerToRawData) const
{
	return peDebugEntryPointerToRawData(peFile->debugDir(), index, pointerToRawData);
}

unsigned long long PeFormatParser32::getResourceDirectoryOffset() const
{
	return peResourceDirectoryOffset(peFile->resDir());
}

const PeLib::ResourceNode* PeFormatParser32::getResourceTreeRoot() const
{
	return peResourceTreeRoot(peFile->resDir());
}

std::unique_ptr<CLRHeader> PeFormatParser32::getClrHeader() const
{
	return peGetClrHeader(peFile->comDir());
}

unsigned long long PeFormatParser32::getNumberOfRelocations() const
{
	return peNumberOfRelocations(peFile->relocDir());
}

unsigned long long PeFormatParser32::getNumberOfRelocationData(unsigned long long index) const
{
	return peNumberOfRelocationData(peFile->relocDir(), index);
}

unsigned long long PeFormatParser32::getChecksumFileOffset() const
{
	return peChecksumFileOffset(peHeader);
}

unsigned long long PeFormatParser32::getSecurityDirFileOffset() const
{
	return peSecurityDirFileOffset(peHeader);
}

unsigned long long PeFormatParser32::getSecurityDirRva() const
{
	return peSecurityDirRva(peHeader);
}

unsigned long long PeFormatParser32::getSecurityDirSize() const
{
	return peSecurityDirSize(peHeader);
}

retdec::utils::RangeContainer<std::uint64_t> PeFormatParser32::getImportDirectoryOccupiedAddresses() const
{
	return peImportDirectoryOccupiedAddresses(peFile->impDir());
}

retdec::utils::RangeContainer<std::uint64_t> PeFormatParser32::getExportDirectoryOccupiedAddresses() const
{
	return peExportDirectoryOccupiedAddresses(peFile->expDir());
}

retdec::utils::RangeContainer<std::uint64_t> PeFormatParser32::getDebugDirectoryOccupiedAddresses() const
{
	return peDebugDirectoryOccupiedAddresses(peFile->debugDir());
}

retdec::utils::RangeContainer<std::uint64_t> PeFormatParser32::getResourceDirectoryOccupiedAddresses() const
{
	return peResourceDirectoryOccupiedAddresses(peFile->resDir());
}

} // namespace fileformat
} // namespace retdec
