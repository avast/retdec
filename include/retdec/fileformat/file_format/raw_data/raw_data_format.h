/**
 * @file include/retdec/fileformat/file_format/raw_data/raw_data_format.h
 * @brief Definition of RawDataFormat class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_FILE_FORMAT_RAW_DATA_RAW_DATA_FORMAT_H
#define RETDEC_FILEFORMAT_FILE_FORMAT_RAW_DATA_RAW_DATA_FORMAT_H

#include <cassert>

#include "retdec/utils/address.h"
#include "retdec/fileformat/file_format/file_format.h"

namespace retdec {
namespace fileformat {

/**
 * RawDataFormat - dummy format that allows you to create file format instance
 * and fill it with custom data.
 *
 * This format is designed for unit-testing of fileformat and other related
 * modules and functions. It should allow easy modifications of internal
 * @c FileFormat structures without modification of implementation of other
 * real-world formats.
 *
 * Currently, the format have a single data section located at 0x0 memory
 * address. Default architecture is x86 -- because architecture it can not
 * be unknown, because in such a case some needed values are not initialized
 * (e.g. bytes per word). Default endian is set to little, since all machines
 * we run unit tests on are little -- format allows you to add custom data to
 * data section through simple one-to-one copy.
 */
class RawDataFormat : public FileFormat
{
	private:
		Section *section = nullptr;
		std::string secName = ".data";
		Section::Type secType = Section::Type::DATA;
		bool hasEntryPoint = false;
		unsigned long long epAddress = 0;

		std::size_t bytesPerWord = 4;
		std::size_t bytesLength = 8;
		Architecture architecture = Architecture::X86;
		retdec::utils::Endianness endianness = retdec::utils::Endianness::LITTLE;

		/// @name Initialization methods
		/// @{
		void initStructures();
		/// @}

		/// @name Virtual initialization methods
		/// @{
		virtual std::size_t initSectionTableHashOffsets() override;
		/// @}

		/// @name Auxiliary methods
		/// @{
		bool isEntryPointValid() const;
		/// @}

	public:
		RawDataFormat(std::istream &inputStream, LoadFlags loadFlags = LoadFlags::NONE);
		RawDataFormat(const std::string &filePath, LoadFlags loadFlags = LoadFlags::NONE);
		virtual ~RawDataFormat() override;

		/// @name Byte value storage methods
		/// @{
		virtual retdec::utils::Endianness getEndianness() const override;
		virtual std::size_t getBytesPerWord() const override;
		virtual std::size_t getByteLength() const override;
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
		virtual bool getEpOffset(unsigned long long &result) const override;
		virtual Architecture getTargetArchitecture() const override;
		virtual std::size_t getDeclaredNumberOfSections() const override;
		virtual std::size_t getDeclaredNumberOfSegments() const override;
		virtual std::size_t getSectionTableOffset() const override;
		virtual std::size_t getSectionTableEntrySize() const override;
		virtual std::size_t getSegmentTableOffset() const override;
		virtual std::size_t getSegmentTableEntrySize() const override;
		/// @}

		/// @name @c Raw binary specific setters
		/// Since raw binary files are missing some critical information about
		/// the binary, we need to manually set them before using its representation
		/// in the decompilation toolchain.
		/// @{
		void setTargetArchitecture(Architecture a);
		void setEndianness(retdec::utils::Endianness e);
		void setBytesPerWord(std::size_t b);
		void setBytesLength(std::size_t l);
		void setEntryPoint(retdec::utils::Address entryPoint);
		void setBaseAddress(retdec::utils::Address baseAddress);
		/// @}

		/**
		 * Append any data to @c section data.
		 * @param d Data to append.
		 * @return Address in memory where data were added.
		 * @note Data are simply copied to the end of the first section's binary
		 * data and to the end of file stream. The size of data is determined by
		 * sizeof(), so keep this in mind when using it -- it is ok to append
		 * C basic and composite types, but appending high-level abstract
		 * C++ types (e.g. vectors) makes no sense and will not produce an
		 * expected result.
		 */
		template<typename T>
		std::size_t appendData(const T &d)
		{
			const auto *pd = reinterpret_cast<const unsigned char*>(&d);
			assert(pd && "Invalid data");
			assert(section && "Section must be initialized in constructor");
			std::vector<unsigned char> aBytes(pd, pd + sizeof(d));
			const auto pos = bytes.size();
			bytes.insert(bytes.end(), aBytes.begin(), aBytes.end());
			section->setSizeInFile(bytes.size());
			section->setSizeInMemory(bytes.size());
			section->load(this);
			return section->getAddress() + pos;
		}

		std::string dumpData() const;
};

} // namespace fileformat
} // namespace retdec

#endif
