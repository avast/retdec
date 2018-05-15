/**
 * @file src/fileformat/file_format/pe/pe_format_parser/pe_format_parser64.cpp
 * @brief Methods of PeFormatParser64 class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/file_format/file_format.h"
#include "retdec/fileformat/file_format/pe/pe_format_parser/pe_format_parser64.h"
#include "retdec/fileformat/file_format/pe/pe_template.h"

using namespace PeLib;

namespace retdec {
namespace fileformat {

/**
 * Constructor
 * @param fInputFile Pointer to input file
 * @param peFile64 64-bit PE file
 */
PeFormatParser64::PeFormatParser64(const FileFormat *fInputFile, PeLib::PeFileT<64> *peFile64) : PeFormatParser(fInputFile),
	peFile(peFile64), peHeader(peFile64->peHeader())
{

}

/**
 * Destructor
 */
PeFormatParser64::~PeFormatParser64()
{

}

unsigned long long PeFormatParser64::getDeclaredNumberOfSections() const
{
	return peDeclaredNumberOfSections(peHeader);
}

unsigned long long PeFormatParser64::getStoredNumberOfSections() const
{
	return peStoredNumberOfSections(peHeader);
}

unsigned long long PeFormatParser64::getMachineType() const
{
	return peHeader.getMachine();
}

unsigned long long PeFormatParser64::getImageBaseAddress() const
{
	return peImageBase(peHeader);
}

unsigned long long PeFormatParser64::getCoffSymbolTableOffset() const
{
	return peCoffSymbolTableOffset(peHeader);
}

unsigned long long PeFormatParser64::getNumberOfCoffSymbols() const
{
	return peNumberOfCoffSymbols(peHeader);
}

unsigned long long PeFormatParser64::getMajorLinkerVersion() const
{
	return peMajorLinkerVersion(peHeader);
}

unsigned long long PeFormatParser64::getMinorLinkerVersion() const
{
	return peMinorLinkerVersion(peHeader);
}

unsigned long long PeFormatParser64::getFileFlags() const
{
	return peFileFlags(peHeader);
}

unsigned long long PeFormatParser64::getTimeStamp() const
{
	return peTimeStamp(peHeader);
}

unsigned long long PeFormatParser64::getOptionalHeaderSize() const
{
	return peSizeOfOptionalHeader(peHeader);
}

unsigned long long PeFormatParser64::getFileAlignment() const
{
	return peFileAlignment(peHeader);
}

unsigned long long PeFormatParser64::getSectionAlignment() const
{
	return peSectionAlignment(peHeader);
}

unsigned long long PeFormatParser64::getSizeOfImage() const
{
	return peSizeOfImage(peHeader);
}

unsigned long long PeFormatParser64::getChecksum() const
{
	return peChecksum(peHeader);
}

unsigned long long PeFormatParser64::getSizeOfStackReserve() const
{
	return peSizeOfStackReserve(peHeader);
}

unsigned long long PeFormatParser64::getSizeOfStackCommit() const
{
	return peSizeOfStackCommit(peHeader);
}

unsigned long long PeFormatParser64::getSizeOfHeapReserve() const
{
	return peSizeOfHeapReserve(peHeader);
}

unsigned long long PeFormatParser64::getSizeOfHeapCommit() const
{
	return peSizeOfHeapCommit(peHeader);
}

unsigned long long PeFormatParser64::getSizeOfPeSignature() const
{
	return peSizeOfPeSignature(peHeader);
}

unsigned long long PeFormatParser64::getLoadedSizeOfNtHeaders() const
{
	return peLoadedSizeOfNtHeaders(peHeader);
}

unsigned long long PeFormatParser64::getAllocatedSizeOfNtHeaders() const
{
	return peAllocatedSizeOfNtHeaders(peHeader);
}

unsigned long long PeFormatParser64::getDeclaredNumberOfDataDirectories() const
{
	return peNumberOfDeclaredDataDirectories(peHeader);
}

unsigned long long PeFormatParser64::getStoredNumberOfDataDirectories() const
{
	return peNumberOfStoredDataDirectories(peHeader);
}

unsigned long long PeFormatParser64::getNumberOfImportedLibraries() const
{
	return peNumberOfImportedLibraries(peFile->impDir());
}

unsigned long long PeFormatParser64::getNumberOfDelayImportedLibraries() const
{
	return peNumberOfDelayImportedLibraries(peFile->delayImports());
}

bool PeFormatParser64::isDll() const
{
	return peIsDll(peHeader);
}

bool PeFormatParser64::getEpAddress(unsigned long long &epAddress) const
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

bool PeFormatParser64::getEpOffset(unsigned long long &epOffset) const
{
	unsigned long long epAddress = 0;
	if(!getEpAddress(epAddress))
	{
		return false;
	}

	const auto offset = peEpOffset(peHeader);
	if(offset == std::numeric_limits<qword>::max())
	{
		return false;
	}

	epOffset = offset;
	return true;
}

bool PeFormatParser64::getSection(unsigned long long secIndex, PeCoffSection &section) const
{
	return peSectionWithIndex(inputFile, peHeader, section, secIndex);
}

bool PeFormatParser64::getDllFlags(unsigned long long &dllFlags) const
{
	return peDllFlags(peHeader, dllFlags);
}

bool PeFormatParser64::getDataDirectoryRelative(unsigned long long index, unsigned long long &relAddr, unsigned long long &size) const
{
	return peDataDirectoryRelative(peHeader, relAddr, size, index);
}

bool PeFormatParser64::getDataDirectoryAbsolute(unsigned long long index, unsigned long long &absAddr, unsigned long long &size) const
{
	return peDataDirectoryAbsolute(peHeader, absAddr, size, index);
}

bool PeFormatParser64::getImportedLibraryFileName(unsigned long long index, std::string &fileName) const
{
	return peImportedLibraryFileName(peFile->impDir(), fileName, index);
}

bool PeFormatParser64::getDelayImportedLibraryFileName(unsigned long long index, std::string &fileName) const
{
	return peDelayImportedLibraryFileName(peFile->delayImports(), fileName, index);
}

std::unique_ptr<PeImport> PeFormatParser64::getImport(unsigned long long fileIndex, unsigned long long importIndex) const
{
	return peImport(peHeader, peFile->impDir(), fileIndex, importIndex);
}

std::unique_ptr<PeImport> PeFormatParser64::getDelayImport(unsigned long long fileIndex, unsigned long long importIndex) const
{
	return peDelayImport(peHeader, peFile->delayImports(), fileIndex, importIndex);
}

unsigned long long PeFormatParser64::getNumberOfExportedFunctions() const
{
	return peNumberOfExportedFunctions(peFile->expDir());
}

bool PeFormatParser64::getExportedFunction(unsigned long long index, Export &exportedFunction) const
{
	return peExportedFunction(peHeader, peFile->expDir(), index, exportedFunction);
}

unsigned long long PeFormatParser64::getNumberOfDebugEntries() const
{
	return peNumberOfDebugEntries(peFile->debugDir());
}

bool PeFormatParser64::getDebugEntryData(unsigned long long index, std::vector<std::uint8_t>& data) const
{
	return peDebugEntryData(peFile->debugDir(), index, data);
}

bool PeFormatParser64::getDebugEntryTimeDateStamp(unsigned long long index, unsigned long long& timeDateStamp) const
{
	return peDebugEntryTimeDateStamp(peFile->debugDir(), index, timeDateStamp);
}

bool PeFormatParser64::getDebugEntryPointerToRawData(unsigned long long index, unsigned long long& pointerToRawData) const
{
	return peDebugEntryPointerToRawData(peFile->debugDir(), index, pointerToRawData);
}

unsigned long long PeFormatParser64::getResourceDirectoryOffset() const
{
	return peResourceDirectoryOffset(peFile->resDir());
}

const PeLib::ResourceNode* PeFormatParser64::getResourceTreeRoot() const
{
	return peResourceTreeRoot(peFile->resDir());
}

std::unique_ptr<CLRHeader> PeFormatParser64::getClrHeader() const
{
	return peGetClrHeader(peFile->comDir());
}

unsigned long long PeFormatParser64::getNumberOfRelocations() const
{
	return peNumberOfRelocations(peFile->relocDir());
}

unsigned long long PeFormatParser64::getNumberOfRelocationData(unsigned long long index) const
{
	return peNumberOfRelocationData(peFile->relocDir(), index);
}

unsigned long long PeFormatParser64::getChecksumFileOffset() const
{
	return peChecksumFileOffset(peHeader);
}

unsigned long long PeFormatParser64::getSecurityDirFileOffset() const
{
	return peSecurityDirFileOffset(peHeader);
}

unsigned long long PeFormatParser64::getSecurityDirRva() const
{
	return peSecurityDirRva(peHeader);
}

unsigned long long PeFormatParser64::getSecurityDirSize() const
{
	return peSecurityDirSize(peHeader);
}

retdec::utils::RangeContainer<std::uint64_t> PeFormatParser64::getImportDirectoryOccupiedAddresses() const
{
	return peImportDirectoryOccupiedAddresses(peFile->impDir());
}

retdec::utils::RangeContainer<std::uint64_t> PeFormatParser64::getExportDirectoryOccupiedAddresses() const
{
	return peExportDirectoryOccupiedAddresses(peFile->expDir());
}

retdec::utils::RangeContainer<std::uint64_t> PeFormatParser64::getDebugDirectoryOccupiedAddresses() const
{
	return peDebugDirectoryOccupiedAddresses(peFile->debugDir());
}

retdec::utils::RangeContainer<std::uint64_t> PeFormatParser64::getResourceDirectoryOccupiedAddresses() const
{
	return peResourceDirectoryOccupiedAddresses(peFile->resDir());
}

} // namespace fileformat
} // namespace retdec
