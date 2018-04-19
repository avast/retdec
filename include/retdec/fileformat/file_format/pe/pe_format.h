/**
 * @file include/retdec/fileformat/file_format/pe/pe_format.h
 * @brief Definition of PeFormat class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_FILE_FORMAT_PE_PE_FORMAT_H
#define RETDEC_FILEFORMAT_FILE_FORMAT_PE_PE_FORMAT_H

#include <pelib/PeLib.h>

#include "retdec/crypto/hash_context.h"
#include "retdec/fileformat/file_format/file_format.h"
#include "retdec/fileformat/file_format/pe/pe_format_parser/pe_format_parser.h"
#include "retdec/fileformat/types/dotnet_headers/blob_stream.h"
#include "retdec/fileformat/types/dotnet_headers/guid_stream.h"
#include "retdec/fileformat/types/dotnet_headers/metadata_stream.h"
#include "retdec/fileformat/types/dotnet_headers/string_stream.h"
#include "retdec/fileformat/types/dotnet_headers/user_string_stream.h"
#include "retdec/fileformat/types/dotnet_types/dotnet_class.h"

namespace retdec {
namespace fileformat {

/**
 * PeFormat - wrapper for parsing PE files
 */
class PeFormat : public FileFormat
{
	private:
		PeFormatParser *formatParser;                              ///< parser of PE file
		PeLib::MzHeader mzHeader;                                  ///< MZ header
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

		/// @name Initialization methods
		/// @{
		void initLoaderErrorInfo();
		void initStructures();
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
		void loadPdbInfo();
		void loadResourceNodes(std::vector<const PeLib::ResourceChild*> &nodes, const std::vector<std::size_t> &levels);
		void loadResources();
		void loadCertificates();
		/// @}

		/// @name Signature verification methods
		/// @{
		bool verifySignature(PKCS7 *p7);
		std::vector<std::tuple<const std::uint8_t*, std::size_t>> getDigestRanges() const;
		std::string calculateDigest(retdec::crypto::HashAlgorithm hashType) const;
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
		/// @}
	protected:
		PeLib::PeFile *file;              ///< PeLib representation of PE file
		PeLib::PeHeaderT<32> *peHeader32; ///< header of 32-bit PE file
		PeLib::PeHeaderT<64> *peHeader64; ///< header of 64-bit PE file
		int peClass;                      ///< class of PE file
	public:
		PeFormat(std::string pathToFile, LoadFlags loadFlags = LoadFlags::NONE);
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
		virtual bool getMachineCode(unsigned long long &result) const override;
		virtual bool getAbiVersion(unsigned long long &result) const override;
		virtual bool getImageBaseAddress(unsigned long long &imageBase) const override;
		virtual bool getEpAddress(unsigned long long &result) const override;
		virtual bool getEpOffset(unsigned long long &epOffset) const override;
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
		std::size_t getMzHeaderSize() const;
		std::size_t getOptionalHeaderSize() const;
		std::size_t getPeHeaderOffset() const;
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
		std::size_t getSizeOfImage() const;
		std::size_t getSizeOfStackReserve() const;
		std::size_t getSizeOfStackCommit() const;
		std::size_t getSizeOfHeapReserve() const;
		std::size_t getSizeOfHeapCommit() const;
		std::size_t getNumberOfDataDirectories() const;
		std::size_t getDeclaredNumberOfDataDirectories() const;

		int getPeClass() const;
		bool isDotNet() const;
		bool isPackedDotNet() const;
		bool isVisualBasic(unsigned long long &version) const;
		bool getDllFlags(unsigned long long &dllFlags) const;
		bool getNumberOfBaseRelocationBlocks(unsigned long long &relocs) const;
		bool getNumberOfRelocations(unsigned long long &relocs) const;
		bool getDataDirectoryRelative(unsigned long long index, unsigned long long &relAddr, unsigned long long &size) const;
		bool getDataDirectoryAbsolute(unsigned long long index, unsigned long long &absAddr, unsigned long long &size) const;
		const PeCoffSection* getPeSection(const std::string &secName) const;
		const PeCoffSection* getPeSection(unsigned long long secIndex) const;
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
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
