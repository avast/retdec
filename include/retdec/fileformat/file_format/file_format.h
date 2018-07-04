/**
 * @file include/retdec/fileformat/file_format/file_format.h
 * @brief Definition of FileFormat class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_FILE_FORMAT_FILE_FORMAT_H
#define RETDEC_FILEFORMAT_FILE_FORMAT_FILE_FORMAT_H

#include <fstream>
#include <initializer_list>
#include <map>
#include <set>
#include <vector>

#include "retdec/config/config.h"
#include "retdec/utils/byte_value_storage.h"
#include "retdec/utils/non_copyable.h"
#include "retdec/fileformat/fftypes.h"

namespace retdec {
namespace fileformat {

/**
* LoaderErrorInfo - common structure that contains loader error code, error message and user-friendly error message
*/

struct LoaderErrorInfo
{
	LoaderErrorInfo() : loaderErrorCode(0), loaderError(nullptr), loaderErrorUserFriendly(nullptr)
	{}

	std::uint32_t loaderErrorCode;               // Loader error code, cast to uint32_t
	const char * loaderError;
	const char * loaderErrorUserFriendly;
};

/**
 * FileFormat - abstract class for parsing files
 */
class FileFormat : public retdec::utils::ByteValueStorage, private retdec::utils::NonCopyable
{
	private:
		std::ifstream auxStream;                 ///< auxiliary member for opening of input file
		std::vector<unsigned char> *loadedBytes; ///< reference to serialized content of input file
		LoadFlags loadFlags;                     ///< load flags for configurable file loading

		/// @name Initialization methods
		/// @{
		void init();
		void initStream();
		template<typename T> void initFormatArch(T derivedPtr, const retdec::config::Architecture &arch);
		/// @}

		/// @name Pure virtual initialization methods
		/// @{
		virtual std::size_t initSectionTableHashOffsets() = 0;
		/// @}
	protected:
		std::string crc32;                                                ///< CRC32 of file content
		std::string md5;                                                  ///< MD5 of file content
		std::string sha256;                                               ///< SHA256 of file content
		std::string sectionCrc32;                                         ///< CRC32 of section table
		std::string sectionMd5;                                           ///< MD5 of section table
		std::string sectionSha256;                                        ///< SHA256 of section table
		std::string filePath;                                             ///< name of input file
		std::istream &fileStream;                                         ///< stream representation of input file
		std::vector<Section*> sections;                                   ///< file sections
		std::vector<Segment*> segments;                                   ///< file segments
		std::vector<SymbolTable*> symbolTables;                           ///< symbol tables
		std::vector<RelocationTable*> relocationTables;                   ///< relocation tables
		std::vector<DynamicTable*> dynamicTables;                         ///< tables with dynamic records
		std::vector<unsigned char> bytes;                                 ///< content of file as bytes
		std::vector<String> strings;                                      ///< detected strings
		std::vector<ElfNoteSecSeg> noteSecSegs;                           ///< note sections or segemnts found in ELF file
		std::set<std::uint64_t> unknownRelocs;                            ///< unknown relocations
		ImportTable *importTable;                                         ///< table of imports
		ExportTable *exportTable;                                         ///< table of exports
		ResourceTable *resourceTable;                                     ///< table of resources
		ResourceTree *resourceTree;                                       ///< structure of resource tree
		RichHeader *richHeader;                                           ///< rich header
		PdbInfo *pdbInfo;                                                 ///< information about related PDB debug file
		CertificateTable *certificateTable;                               ///< table of certificates
		ElfCoreInfo *elfCoreInfo;                                         ///< information about core file structures
		Format fileFormat;                                                ///< format of input file
		LoaderErrorInfo _ldrErrInfo;                                      ///< loader error (e.g. Windows loader error for PE files)
		bool stateIsValid;                                                ///< internal state of instance
		std::vector<std::pair<std::size_t, std::size_t>> secHashInfo;     ///< information for calculation of section table hash
		retdec::utils::Maybe<bool> signatureVerified;                     ///< indicates whether the signature is present and also verified
		retdec::utils::RangeContainer<std::uint64_t> nonDecodableRanges;  ///< Address ranges which should not be decoded for instructions.

		/// @name Clear methods
		/// @{
		void clear();
		/// @}

		/// @name Protected detection methods
		/// @{
		void computeSectionTableHashes();
		/// @}

		/// @name Setters
		/// @{
		void setLoadedBytes(std::vector<unsigned char> *lBytes);
		/// @}

		FileFormat(std::istream &inputStream, LoadFlags loadFlags = LoadFlags::NONE);
	public:
		FileFormat(std::string pathToFile, LoadFlags loadFlags = LoadFlags::NONE);
		virtual ~FileFormat();

		/// @name Other methods
		/// @{
		void initFromConfig(const retdec::config::Config &config);
		void loadStrings();
		void loadStrings(StringType type, std::size_t charSize);
		void loadStrings(StringType type, std::size_t charSize, const SecSeg* secSeg);
		void loadImpHash();
		void loadExpHash();
		bool isInValidState() const;
		LoadFlags getLoadFlags() const;
		/// @}

		/// @name Auxiliary offset detection methods
		/// @{
		const Section* getSectionFromOffset(unsigned long long offset) const;
		const Segment* getSegmentFromOffset(unsigned long long offset) const;
		const SecSeg* getSectionOrSegmentFromOffset(unsigned long long offset) const;
		bool haveSectionOrSegmentOnOffset(unsigned long long offset) const;
		bool haveDataOnOffset(unsigned long long offset) const;
		/// @}

		/// @name Auxiliary address detection methods
		/// @{
		const Section* getSectionFromAddress(unsigned long long address) const;
		const Segment* getSegmentFromAddress(unsigned long long address) const;
		const SecSeg* getSectionOrSegmentFromAddress(unsigned long long address) const;
		bool haveSectionOrSegmentOnAddress(unsigned long long address) const;
		bool haveDataOnAddress(unsigned long long address) const;
		bool haveReadOnlyDataOnAddress(unsigned long long address) const;
		/// @}

		/// @name Byte value storage methods
		/// @{
		virtual std::size_t getNibbleLength() const override;
		virtual std::size_t getByteLength() const override;
		virtual std::size_t getWordLength() const override;
		virtual std::size_t getNumberOfNibblesInByte() const override;

		/// @}
		const LoaderErrorInfo & getLoaderErrorInfo() const;

		/// @name Detection methods
		/// @{
		bool isX86() const;
		bool isX86_64() const;
		bool isX86OrX86_64() const;
		bool isArm() const;
		bool isPowerPc() const;
		bool isMips() const;
		bool isUnknownArch() const;
		bool isPe() const;
		bool isElf() const;
		bool isCoff() const;
		bool isMacho() const;
		bool isIntelHex() const;
		bool isRawData() const;
		bool isUnknownFormat() const;
		bool isWindowsDriver() const;
		bool hasCrc32() const;
		bool hasMd5() const;
		bool hasSha256() const;
		bool hasSectionTableCrc32() const;
		bool hasSectionTableMd5() const;
		bool hasSectionTableSha256() const;
		std::string getCrc32() const;
		std::string getMd5() const;
		std::string getSha256() const;
		std::string getSectionTableCrc32() const;
		std::string getSectionTableMd5() const;
		std::string getSectionTableSha256() const;
		std::string getPathToFile() const;
		std::istream& getFileStream();
		Format getFileFormat() const;
		std::size_t getNumberOfSections() const;
		std::size_t getNumberOfSegments() const;
		std::size_t getNumberOfSymbolTables() const;
		std::size_t getNumberOfRelocationTables() const;
		std::size_t getNumberOfDynamicTables() const;
		std::size_t getFileLength() const;
		std::size_t getLoadedFileLength() const;
		std::size_t getOverlaySize() const;
		std::size_t nibblesFromBytes(std::size_t bytes) const;
		std::size_t bytesFromNibbles(std::size_t nibbles) const;
		std::size_t bytesFromNibblesRounded(std::size_t nibbles) const;
		bool getOffsetFromAddress(unsigned long long &result, unsigned long long address) const;
		bool getAddressFromOffset(unsigned long long &result, unsigned long long offset) const;
		bool getBytes(std::vector<std::uint8_t> &result, unsigned long long offset, unsigned long long numberOfBytes) const;
		bool getEpBytes(std::vector<std::uint8_t> &result, unsigned long long numberOfBytes) const;
		bool getHexBytes(std::string &result, unsigned long long offset, unsigned long long numberOfBytes) const;
		bool getHexEpBytes(std::string &result, unsigned long long numberOfBytes) const;
		bool getHexBytesFromEnd(std::string &result, unsigned long long numberOfBytes) const;
		bool getString(std::string &result, unsigned long long offset, unsigned long long numberOfBytes) const;
		bool getStringFromEnd(std::string &result, unsigned long long numberOfBytes) const;
		const Section* getEpSection();
		const Section* getSection(const std::string &secName) const;
		const Section* getSection(unsigned long long secIndex) const;
		const Section* getLastSection() const;
		const Section* getLastButOneSection() const;
		const Segment* getEpSegment();
		const Segment* getSegment(const std::string &segName) const;
		const Segment* getSegment(unsigned long long segIndex) const;
		const Segment* getLastSegment() const;
		const Segment* getLastButOneSegment() const;
		const SymbolTable* getSymbolTable(unsigned long long tabIndex) const;
		const RelocationTable* getRelocationTable(unsigned long long tabIndex) const;
		const DynamicTable* getDynamicTable(unsigned long long tabIndex) const;
		const ImportTable* getImportTable() const;
		const ExportTable* getExportTable() const;
		const ResourceTable* getResourceTable() const;
		const ResourceTree* getResourceTree() const;
		const RichHeader* getRichHeader() const;
		const PdbInfo* getPdbInfo() const;
		const CertificateTable* getCertificateTable() const;
		const ElfCoreInfo* getElfCoreInfo() const;
		const Symbol* getSymbol(const std::string &name) const;
		const Symbol* getSymbol(unsigned long long address) const;
		const Relocation* getRelocation(const std::string &name) const;
		const Relocation* getRelocation(unsigned long long address) const;
		const Import* getImport(const std::string &name) const;
		const Import* getImport(unsigned long long address) const;
		const Export* getExport(const std::string &name) const;
		const Export* getExport(unsigned long long address) const;
		const Resource* getManifestResource() const;
		const Resource* getVersionResource() const;
		bool isSignaturePresent() const;
		bool isSignatureVerified() const;
		const retdec::utils::RangeContainer<std::uint64_t>& getNonDecodableAddressRanges() const;
		/// @}

		/// @name Containers
		/// @{
		const std::vector<Section*>& getSections() const;
		const std::vector<Section*> getSections(std::initializer_list<std::string> secs) const;
		const std::vector<Segment*>& getSegments() const;
		const std::vector<Segment*> getSegments(std::initializer_list<std::string> segs) const;
		const std::vector<SymbolTable*>& getSymbolTables() const;
		const std::vector<RelocationTable*>& getRelocationTables() const;
		const std::vector<DynamicTable*>& getDynamicTables() const;
		const std::vector<unsigned char>& getBytes() const;
		const std::vector<unsigned char>& getLoadedBytes() const;
		const unsigned char* getBytesData() const;
		const unsigned char* getLoadedBytesData() const;
		const std::vector<String>& getStrings() const;
		const std::vector<ElfNoteSecSeg>& getElfNoteSecSegs() const;
		const std::set<std::uint64_t>& getUnknownRelocations() const;
		/// @}

		/// @name Address interpretation methods
		/// @{
		virtual bool getXByte(std::uint64_t address, std::uint64_t x, std::uint64_t &res, retdec::utils::Endianness e = retdec::utils::Endianness::UNKNOWN) const override;
		virtual bool getXBytes(std::uint64_t address, std::uint64_t x, std::vector<std::uint8_t> &res) const override;
		virtual bool setXByte(std::uint64_t address, std::uint64_t x, std::uint64_t val, retdec::utils::Endianness e = retdec::utils::Endianness::UNKNOWN) override;
		virtual bool setXBytes(std::uint64_t address, const std::vector<std::uint8_t> &val) override;
		bool isPointer(unsigned long long address, std::uint64_t* pointer = nullptr) const;
		/// @}

		/// @name Offset interpretation methods
		/// @{
		bool get1ByteOffset(std::uint64_t offset, std::uint64_t &res, retdec::utils::Endianness e = retdec::utils::Endianness::UNKNOWN) const;
		bool get2ByteOffset(std::uint64_t offset, std::uint64_t &res, retdec::utils::Endianness e = retdec::utils::Endianness::UNKNOWN) const;
		bool get4ByteOffset(std::uint64_t offset, std::uint64_t &res, retdec::utils::Endianness e = retdec::utils::Endianness::UNKNOWN) const;
		bool get8ByteOffset(std::uint64_t offset, std::uint64_t &res, retdec::utils::Endianness e = retdec::utils::Endianness::UNKNOWN) const;
		bool get10ByteOffset(std::uint64_t offset, long double &res) const;
		bool getXByteOffset(std::uint64_t offset, std::uint64_t x, std::uint64_t &res, retdec::utils::Endianness e = retdec::utils::Endianness::UNKNOWN) const;
		bool getXBytesOffset(std::uint64_t offset, std::uint64_t x, std::vector<std::uint8_t> &res) const;
		bool getWordOffset(std::uint64_t offset, std::uint64_t &res, retdec::utils::Endianness e = retdec::utils::Endianness::UNKNOWN) const;
		bool getNTBSOffset(std::uint64_t offset, std::string &res, std::size_t size = 0) const;
		bool getNTWSOffset(std::uint64_t offset, std::size_t width, std::vector<std::uint64_t> &res) const;
		/// @}

		/// @name Virtual detection methods
		/// @{
		virtual std::string getFileFormatName() const;
		virtual std::size_t getDeclaredFileLength() const;
		virtual bool areSectionsValid() const;
		/// @}

		/// @name Pure virtual detection methods
		/// @{
		virtual bool isObjectFile() const = 0;
		virtual bool isDll() const = 0;
		virtual bool isExecutable() const = 0;
		virtual bool getMachineCode(unsigned long long &result) const = 0;
		virtual bool getAbiVersion(unsigned long long &result) const = 0;
		virtual bool getImageBaseAddress(unsigned long long &imageBase) const = 0;
		virtual bool getEpAddress(unsigned long long &result) const = 0;
		virtual bool getEpOffset(unsigned long long &epOffset) const = 0;
		virtual Architecture getTargetArchitecture() const = 0;
		virtual std::size_t getDeclaredNumberOfSections() const = 0;
		virtual std::size_t getDeclaredNumberOfSegments() const = 0;
		virtual std::size_t getSectionTableOffset() const = 0;
		virtual std::size_t getSectionTableEntrySize() const = 0;
		virtual std::size_t getSegmentTableOffset() const = 0;
		virtual std::size_t getSegmentTableEntrySize() const = 0;
		/// @}

		/// @name Dump methods
		/// @{
		void dump();
		void dump(std::string &dumpFile);
		void dumpRegionsValidity();
		void dumpRegionsValidity(std::string &dumpStr);
		void dumpResourceTree();
		void dumpResourceTree(std::string &dumpStr);
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
