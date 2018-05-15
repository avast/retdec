/**
 * @file include/retdec/fileformat/file_format/pe/pe_format_parser/pe_format_parser64.h
 * @brief Definition of PeFormatParser64 class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_FILE_FORMAT_PE_PE_FORMAT_PARSER_PE_FORMAT_PARSER64_H
#define RETDEC_FILEFORMAT_FILE_FORMAT_PE_PE_FORMAT_PARSER_PE_FORMAT_PARSER64_H

#include "retdec/fileformat/file_format/pe/pe_format_parser/pe_format_parser.h"

namespace retdec {
namespace fileformat {

class PeFormatParser64 : public PeFormatParser
{
	private:
		PeLib::PeFileT<64> *peFile;     ///< 64-bit PE file
		PeLib::PeHeaderT<64> &peHeader; ///< header of 64-bit PE file
	public:
		PeFormatParser64(const FileFormat *fInputFile, PeLib::PeFileT<64> *peFile64);
		virtual ~PeFormatParser64() override;

		/// @name Detection methods
		/// @{
		virtual unsigned long long getDeclaredNumberOfSections() const override;
		virtual unsigned long long getStoredNumberOfSections() const override;
		virtual unsigned long long getMachineType() const override;
		virtual unsigned long long getImageBaseAddress() const override;
		virtual unsigned long long getCoffSymbolTableOffset() const override;
		virtual unsigned long long getNumberOfCoffSymbols() const override;
		virtual unsigned long long getMajorLinkerVersion() const override;
		virtual unsigned long long getMinorLinkerVersion() const override;
		virtual unsigned long long getFileFlags() const override;
		virtual unsigned long long getTimeStamp() const override;
		virtual unsigned long long getOptionalHeaderSize() const override;
		virtual unsigned long long getFileAlignment() const override;
		virtual unsigned long long getSectionAlignment() const override;
		virtual unsigned long long getSizeOfImage() const override;
		virtual unsigned long long getChecksum() const override;
		virtual unsigned long long getSizeOfStackReserve() const override;
		virtual unsigned long long getSizeOfStackCommit() const override;
		virtual unsigned long long getSizeOfHeapReserve() const override;
		virtual unsigned long long getSizeOfHeapCommit() const override;
		virtual unsigned long long getSizeOfPeSignature() const override;
		virtual unsigned long long getLoadedSizeOfNtHeaders() const override;
		virtual unsigned long long getAllocatedSizeOfNtHeaders() const override;
		virtual unsigned long long getDeclaredNumberOfDataDirectories() const override;
		virtual unsigned long long getStoredNumberOfDataDirectories() const override;
		virtual unsigned long long getNumberOfImportedLibraries() const override;
		virtual unsigned long long getNumberOfDelayImportedLibraries() const override;
		virtual bool isDll() const override;
		virtual bool getEpAddress(unsigned long long &epAddress) const override;
		virtual bool getEpOffset(unsigned long long &epOffset) const override;
		virtual bool getSection(unsigned long long secIndex, PeCoffSection &section) const override;
		virtual bool getDllFlags(unsigned long long &dllFlags) const override;
		virtual bool getDataDirectoryRelative(unsigned long long index, unsigned long long &relAddr, unsigned long long &size) const override;
		virtual bool getDataDirectoryAbsolute(unsigned long long index, unsigned long long &absAddr, unsigned long long &size) const override;
		virtual bool getImportedLibraryFileName(unsigned long long index, std::string &fileName) const override;
		virtual bool getDelayImportedLibraryFileName(unsigned long long index, std::string &fileName) const override;
		virtual std::unique_ptr<PeImport> getImport(unsigned long long fileIndex, unsigned long long importIndex) const override;
		virtual std::unique_ptr<PeImport> getDelayImport(unsigned long long fileIndex, unsigned long long importIndex) const override;
		virtual unsigned long long getNumberOfExportedFunctions() const override;
		virtual bool getExportedFunction(unsigned long long index, Export& exportedFunction) const override;
		virtual unsigned long long getNumberOfDebugEntries() const override;
		virtual bool getDebugEntryData(unsigned long long index, std::vector<std::uint8_t>& data) const override;
		virtual bool getDebugEntryTimeDateStamp(unsigned long long index, unsigned long long& timeDateStamp) const override;
		virtual bool getDebugEntryPointerToRawData(unsigned long long index, unsigned long long& pointerToRawData) const override;
		virtual unsigned long long getResourceDirectoryOffset() const override;
		virtual const PeLib::ResourceNode* getResourceTreeRoot() const override;
		virtual std::unique_ptr<CLRHeader> getClrHeader() const override;
		virtual unsigned long long getNumberOfRelocations() const override;
		virtual unsigned long long getNumberOfRelocationData(unsigned long long index) const override;
		virtual unsigned long long getChecksumFileOffset() const override;
		virtual unsigned long long getSecurityDirFileOffset() const override;
		virtual unsigned long long getSecurityDirRva() const override;
		virtual unsigned long long getSecurityDirSize() const override;
		virtual retdec::utils::RangeContainer<std::uint64_t> getImportDirectoryOccupiedAddresses() const override;
		virtual retdec::utils::RangeContainer<std::uint64_t> getExportDirectoryOccupiedAddresses() const override;
		virtual retdec::utils::RangeContainer<std::uint64_t> getDebugDirectoryOccupiedAddresses() const override;
		virtual retdec::utils::RangeContainer<std::uint64_t> getResourceDirectoryOccupiedAddresses() const override;
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
