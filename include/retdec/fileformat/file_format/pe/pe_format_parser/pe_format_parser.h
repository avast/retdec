/**
 * @file include/retdec/fileformat/file_format/pe/pe_format_parser/pe_format_parser.h
 * @brief Definition of PeFormatParser class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_FILE_FORMAT_PE_PE_FORMAT_PARSER_PE_FORMAT_PARSER_H
#define RETDEC_FILEFORMAT_FILE_FORMAT_PE_PE_FORMAT_PARSER_PE_FORMAT_PARSER_H

#include <pelib/PeLib.h>

#include "retdec/utils/range.h"
#include "retdec/fileformat/fftypes.h"

namespace retdec {
namespace fileformat {

class FileFormat;

class PeFormatParser
{
	protected:
		const FileFormat *inputFile; ///< pointer to input file
	public:
		PeFormatParser(const FileFormat *fInputFile);
		virtual ~PeFormatParser();

		/// @name Detection methods
		/// @{
		virtual unsigned long long getDeclaredNumberOfSections() const = 0;
		virtual unsigned long long getStoredNumberOfSections() const = 0;
		virtual unsigned long long getMachineType() const = 0;
		virtual unsigned long long getImageBaseAddress() const = 0;
		virtual unsigned long long getCoffSymbolTableOffset() const = 0;
		virtual unsigned long long getNumberOfCoffSymbols() const = 0;
		virtual unsigned long long getMajorLinkerVersion() const = 0;
		virtual unsigned long long getMinorLinkerVersion() const = 0;
		virtual unsigned long long getFileFlags() const = 0;
		virtual unsigned long long getTimeStamp() const = 0;
		virtual unsigned long long getOptionalHeaderSize() const = 0;
		virtual unsigned long long getFileAlignment() const = 0;
		virtual unsigned long long getSectionAlignment() const = 0;
		virtual unsigned long long getSizeOfImage() const = 0;
		virtual unsigned long long getChecksum() const = 0;
		virtual unsigned long long getSizeOfStackReserve() const = 0;
		virtual unsigned long long getSizeOfStackCommit() const = 0;
		virtual unsigned long long getSizeOfHeapReserve() const = 0;
		virtual unsigned long long getSizeOfHeapCommit() const = 0;
		virtual unsigned long long getSizeOfPeSignature() const = 0;
		virtual unsigned long long getLoadedSizeOfNtHeaders() const = 0;
		virtual unsigned long long getAllocatedSizeOfNtHeaders() const = 0;
		virtual unsigned long long getDeclaredNumberOfDataDirectories() const = 0;
		virtual unsigned long long getStoredNumberOfDataDirectories() const = 0;
		virtual unsigned long long getNumberOfImportedLibraries() const = 0;
		virtual unsigned long long getNumberOfDelayImportedLibraries() const = 0;
		virtual bool isDll() const = 0;
		virtual bool getEpAddress(unsigned long long &epAddress) const = 0;
		virtual bool getEpOffset(unsigned long long &epOffset) const = 0;
		virtual bool getSection(unsigned long long secIndex, PeCoffSection &section) const = 0;
		virtual bool getDllFlags(unsigned long long &dllFlags) const = 0;
		virtual bool getDataDirectoryRelative(unsigned long long index, unsigned long long &relAddr, unsigned long long &size) const = 0;
		virtual bool getDataDirectoryAbsolute(unsigned long long index, unsigned long long &absAddr, unsigned long long &size) const = 0;
		virtual bool getImportedLibraryFileName(unsigned long long index, std::string &fileName) const = 0;
		virtual bool getDelayImportedLibraryFileName(unsigned long long index, std::string &fileName) const = 0;
		virtual std::unique_ptr<PeImport> getImport(unsigned long long fileIndex, unsigned long long importIndex) const = 0;
		virtual std::unique_ptr<PeImport> getDelayImport(unsigned long long fileIndex, unsigned long long importIndex) const = 0;
		virtual unsigned long long getNumberOfExportedFunctions() const = 0;
		virtual bool getExportedFunction(unsigned long long index, Export& exportedFunction) const = 0;
		virtual unsigned long long getNumberOfDebugEntries() const = 0;
		virtual bool getDebugEntryData(unsigned long long index, std::vector<std::uint8_t>& data) const = 0;
		virtual bool getDebugEntryTimeDateStamp(unsigned long long index, unsigned long long& timeDateStamp) const = 0;
		virtual bool getDebugEntryPointerToRawData(unsigned long long index, unsigned long long& pointerToRawData) const = 0;
		virtual unsigned long long getResourceDirectoryOffset() const = 0;
		virtual const PeLib::ResourceNode* getResourceTreeRoot() const = 0;
		virtual std::unique_ptr<CLRHeader> getClrHeader() const = 0;
		virtual unsigned long long getNumberOfRelocations() const = 0;
		virtual unsigned long long getNumberOfRelocationData(unsigned long long index) const = 0;
		virtual unsigned long long getChecksumFileOffset() const = 0;
		virtual unsigned long long getSecurityDirFileOffset() const = 0;
		virtual unsigned long long getSecurityDirRva() const = 0;
		virtual unsigned long long getSecurityDirSize() const = 0;
		virtual retdec::utils::RangeContainer<std::uint64_t> getImportDirectoryOccupiedAddresses() const = 0;
		virtual retdec::utils::RangeContainer<std::uint64_t> getExportDirectoryOccupiedAddresses() const = 0;
		virtual retdec::utils::RangeContainer<std::uint64_t> getDebugDirectoryOccupiedAddresses() const = 0;
		virtual retdec::utils::RangeContainer<std::uint64_t> getResourceDirectoryOccupiedAddresses() const = 0;
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
