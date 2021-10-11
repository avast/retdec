/**
 * @file include/retdec/fileformat/file_format/pe/pe_format.h
 * @brief Definition of PeFormat class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_FILE_FORMAT_PE_PE_FORMAT_H
#define RETDEC_FILEFORMAT_FILE_FORMAT_PE_PE_FORMAT_H

#include "retdec/fileformat/file_format/file_format.h"
#include "retdec/fileformat/file_format/pe/pe_format_parser.h"
#include "retdec/fileformat/types/dotnet_headers/blob_stream.h"
#include "retdec/fileformat/types/dotnet_headers/guid_stream.h"
#include "retdec/fileformat/types/dotnet_headers/metadata_stream.h"
#include "retdec/fileformat/types/dotnet_headers/string_stream.h"
#include "retdec/fileformat/types/dotnet_headers/user_string_stream.h"
#include "retdec/fileformat/types/dotnet_types/dotnet_class.h"
#include "retdec/fileformat/types/pe_timestamps/pe_timestamps.h"
#include "retdec/fileformat/types/visual_basic/visual_basic_info.h"
#include "retdec/pelib/PeFile.h"

namespace retdec {
namespace fileformat {

/**
 * PeFormat - wrapper for parsing PE files
 */
class PeFormat : public FileFormat
{
	private:
		PeFormatParser *formatParser;                              ///< parser of PE file
		std::unique_ptr<CLRHeader> clrHeader;                      ///< .NET CLR header
		std::unique_ptr<MetadataHeader> metadataHeader;            ///< .NET metadata header
		std::unique_ptr<MetadataStream> metadataStream;            ///< .NET metadata stream
		std::unique_ptr<BlobStream> blobStream;                    ///< .NET blob stream
		std::unique_ptr<GuidStream> guidStream;                    ///< .NET GUID stream
		std::unique_ptr<StringStream> stringStream;                ///< .NET string stream
		std::unique_ptr<UserStringStream> userStringStream;        ///< .NET user string stream
		std::string moduleVersionId;                               ///< .NET module version ID
		std::string typeLibId;                                     ///< .NET type lib ID
		std::vector<std::shared_ptr<DotnetClass>> definedClasses;  ///< .NET defined class list
		std::vector<std::shared_ptr<DotnetClass>> importedClasses; ///< .NET imported class list
		std::string typeRefHashCrc32;                              ///< .NET typeref table hash as CRC32
		std::string typeRefHashMd5;                                ///< .NET typeref table hash as MD5
		std::string typeRefHashSha256;                             ///< .NET typeref table hash as SHA256
		VisualBasicInfo visualBasicInfo;                           ///< visual basic header information

		std::unordered_set<std::string> dllList;                   ///< Override set of DLLs for checking dependency missing
		bool errorLoadingDllList;                                  ///< If true, then an error happened while loading DLL list

		/// @name Initialization methods
		/// @{
		void initLoaderErrorInfo(PeLib::LoaderError ldrError);
		void initLoaderErrorInfo();
		void initStructures(const std::string & dllListFile);
		/// @}

		/// @name Virtual initialization methods
		/// @{
		virtual std::size_t initSectionTableHashOffsets() override;
		/// @}

		/// @name Auxiliary methods
		/// @{
		std::size_t getRichHeaderOffset(const std::string &plainFile);
		bool getResourceNodes(std::vector<const PeLib::ResourceChild*> &nodes, std::vector<std::size_t> &levels);
		void loadRichHeader();
		void loadSections();
		void loadSymbols();
		void loadImports();
		void loadExports();
		void loadVisualBasicHeader();
		void loadPdbInfo();
		void loadResourceNodes(std::vector<const PeLib::ResourceChild*> &nodes, const std::vector<std::size_t> &levels);
		void loadResources();
		void loadCertificates();
		void loadTlsInformation();
		static bool checkDefaultList(std::string_view);
		/// @}

		/// @name .NET methods
		/// @{
		void loadDotnetHeaders();
		void parseMetadataStream(std::uint64_t baseAddress, std::uint64_t offset, std::uint64_t size);
		void parseBlobStream(std::uint64_t baseAddress, std::uint64_t offset, std::uint64_t size);
		void parseGuidStream(std::uint64_t baseAddress, std::uint64_t offset, std::uint64_t size);
		void parseStringStream(std::uint64_t baseAddress, std::uint64_t offset, std::uint64_t size);
		void parseUserStringStream(std::uint64_t baseAddress, std::uint64_t offset, std::uint64_t size);
		template <typename T> void parseMetadataTable(BaseMetadataTable* table, std::uint64_t& address);
		void detectModuleVersionId();
		void detectTypeLibId();
		void detectDotnetTypes();
		std::uint64_t detectPossibleMetadataHeaderAddress() const;
		void computeTypeRefHashes();
		/// @}
		/// @name Visual Basic methods
		/// @{
		bool parseVisualBasicProjectInfo(std::size_t structureOffset);
		bool parseVisualBasicExternTable(std::size_t structureOffset, std::size_t nEntries);
		bool parseVisualBasicObjectTable(std::size_t structureOffset);
		bool parseVisualBasicObjects(std::size_t structureOffset, std::size_t nObjects);
		bool parseVisualBasicComRegistrationData(std::size_t structureOffset);
		bool parseVisualBasicComRegistrationInfo(std::size_t structureOffset,
												std::size_t comRegDataOffset);
		/// @}
		/// @name Auxiliary scanning methods
		/// @{
		void scanForSectionAnomalies(unsigned anamaliesLimit = 1000);
		void scanForResourceAnomalies();
		void scanForImportAnomalies();
		void scanForExportAnomalies();
		void scanForOptHeaderAnomalies();
		/// @}
	protected:
		PeLib::PeFileT *file;              ///< PeLib representation of PE file
	public:
		PeFormat(const std::string & pathToFile, const std::string & dllListFile, LoadFlags loadFlags = LoadFlags::NONE);
		PeFormat(std::istream &inputStream, LoadFlags loadFlags = LoadFlags::NONE);
		PeFormat(const std::uint8_t *data, std::size_t size, LoadFlags loadFlags = LoadFlags::NONE);
		virtual ~PeFormat() override;

		/// @name Byte value storage methods
		/// @{
		virtual retdec::utils::Endianness getEndianness() const override;
		virtual std::size_t getBytesPerWord() const override;
		virtual bool hasMixedEndianForDouble() const override;
		/// @}

		/// @name Virtual detection methods
		/// @{
		virtual std::size_t getDeclaredFileLength() const override;
		virtual bool areSectionsValid() const override;
		virtual bool isObjectFile() const override;
		virtual bool isDll() const override;
		virtual bool isExecutable() const override;
		virtual bool getMachineCode(std::uint64_t &result) const override;
		virtual bool getAbiVersion(std::uint64_t &result) const override;
		virtual bool getImageBaseAddress(std::uint64_t &imageBase) const override;
		virtual bool getEpAddress(std::uint64_t &result) const override;
		virtual bool getEpOffset(std::uint64_t &epOffset) const override;
		virtual Architecture getTargetArchitecture() const override;
		virtual std::size_t getDeclaredNumberOfSections() const override;
		virtual std::size_t getDeclaredNumberOfSegments() const override;
		virtual std::size_t getSectionTableOffset() const override;
		virtual std::size_t getSectionTableEntrySize() const override;
		virtual std::size_t getSegmentTableOffset() const override;
		virtual std::size_t getSegmentTableEntrySize() const override;
		/// @}

		/// @name Detection methods
		/// @{
		const PeLib::ImageLoader & getImageLoader() const;
		std::size_t getMzHeaderSize() const;
		std::size_t getOptionalHeaderSize() const;
		std::size_t getPeHeaderOffset() const;
		std::size_t getImageBitability() const;
		std::size_t getCoffSymbolTableOffset() const;
		std::size_t getNumberOfCoffSymbols() const;
		std::size_t getSizeOfStringTable() const;
		std::size_t getMajorLinkerVersion() const;
		std::size_t getMinorLinkerVersion() const;
		std::size_t getFileFlags() const;
		std::size_t getTimeStamp() const;
		std::size_t getChecksum() const;
		std::size_t getFileAlignment() const;
		std::size_t getSectionAlignment() const;
		std::size_t getSizeOfHeaders() const;
		std::size_t getSizeOfImage() const;
		std::size_t getSizeOfStackReserve() const;
		std::size_t getSizeOfStackCommit() const;
		std::size_t getSizeOfHeapReserve() const;
		std::size_t getSizeOfHeapCommit() const;
		std::size_t getNumberOfDataDirectories() const;
		std::size_t getDeclaredNumberOfDataDirectories() const;

		/// @name Dependency checking
		/// @{
		bool isMissingDependency(std::string dllname) const;
		bool dllListFailedToLoad() const;
		bool initDllList(const std::string & dllListFile);
		/// @}

		bool isDotNet() const;
		bool isPackedDotNet() const;
		bool isVisualBasic(std::uint64_t &version) const;
		bool getDllFlags(std::uint64_t &dllFlags) const;
		bool getNumberOfBaseRelocationBlocks(std::uint64_t &relocs) const;
		bool getNumberOfRelocations(std::uint64_t &relocs) const;
		bool getDataDirectoryRelative(std::uint64_t index, std::uint64_t &relAddr, std::uint64_t &size) const;
		bool getDataDirectoryAbsolute(std::uint64_t index, std::uint64_t &absAddr, std::uint64_t &size) const;
		bool getComDirectoryRelative(std::uint64_t &relAddr, std::uint64_t &size) const;
		const PeCoffSection* getPeSection(const std::string &secName) const;
		const PeCoffSection* getPeSection(std::uint64_t secIndex) const;
		const CLRHeader* getCLRHeader() const;
		const MetadataHeader* getMetadataHeader() const;
		const MetadataStream* getMetadataStream() const;
		const StringStream* getStringStream() const;
		const BlobStream* getBlobStream() const;
		const GuidStream* getGuidStream() const;
		const UserStringStream* getUserStringStream() const;
		const std::string& getModuleVersionId() const;
		const std::string& getTypeLibId() const;
		const std::vector<std::shared_ptr<DotnetClass>>& getDefinedDotnetClasses() const;
		const std::vector<std::shared_ptr<DotnetClass>>& getImportedDotnetClasses() const;
		const std::string& getTypeRefhashCrc32() const;
		const std::string& getTypeRefhashMd5() const;
		const std::string& getTypeRefhashSha256() const;
		const VisualBasicInfo* getVisualBasicInfo() const;
		std::vector<std::tuple<const std::uint8_t*, std::size_t>> getDigestRanges() const;
		PeTimestamps getTimestamps() const;

		/// @name Scanning methods
		/// @{
		void scanForAnomalies();
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
