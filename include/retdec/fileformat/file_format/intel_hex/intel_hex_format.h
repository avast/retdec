/**
 * @file include/retdec/fileformat/file_format/intel_hex/intel_hex_format.h
 * @brief Definition of IntelHexFormat class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_FILE_FORMAT_INTEL_HEX_INTEL_HEX_FORMAT_H
#define RETDEC_FILEFORMAT_FILE_FORMAT_INTEL_HEX_INTEL_HEX_FORMAT_H

#include "retdec/utils/address.h"
#include "retdec/fileformat/file_format/file_format.h"
#include "retdec/fileformat/file_format/intel_hex/intel_hex_parser/intel_hex_parser.h"

namespace retdec {
namespace fileformat {

/**
 * IntelHexFormat - wrapper for parsing Intel HEX files
 */
class IntelHexFormat : public FileFormat
{
	private:
		IntelHexParser parser;                                                       ///< parser of input file
		Architecture architecture = Architecture::UNKNOWN;                           ///< Intel HEX provides no information about architecture
		retdec::utils::Endianness endianness = retdec::utils::Endianness::UNKNOWN; ///< Intel HEX provides no information about endianness
		std::size_t bytesPerWord = 0;                                                ///< Intel HEX provides no information about word size
		retdec::utils::Address epOffset = 0;                                        ///< offset of entry point
		std::vector<unsigned char> serialized;                                       ///< serialized binary data

		/// @name Initialization methods
		/// @{
		void initStructures();
		void initializeSections();
		/// @}

		/// @name Virtual initialization methods
		/// @{
		virtual std::size_t initSectionTableHashOffsets() override;
		/// @}
	public:
		IntelHexFormat(std::string pathToFile, LoadFlags loadFlags = LoadFlags::NONE);
		IntelHexFormat(std::istream &inputStream, LoadFlags loadFlags = LoadFlags::NONE);
		virtual ~IntelHexFormat() override;

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

		/// @name @c IntelHexFormat specific setters
		/// Since Intel HEX format is missing some critical information about
		/// the binary, we need to manually set them before using its representation
		/// in the decompilation toolchain.
		/// @{
		void setTargetArchitecture(Architecture a);
		void setEndianness(retdec::utils::Endianness e);
		void setBytesPerWord(std::size_t b);
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
