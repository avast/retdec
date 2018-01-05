/**
 * @file include/retdec/fileformat/file_format/coff/coff_format.h
 * @brief Definition of CoffFormat class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_FILE_FORMAT_COFF_COFF_FORMAT_H
#define RETDEC_FILEFORMAT_FILE_FORMAT_COFF_COFF_FORMAT_H

#include <llvm/Object/COFF.h>

#include "retdec/fileformat/file_format/file_format.h"

namespace retdec {
namespace fileformat {

/**
 * CoffFormat - wrapper for parsing COFF files
 */
class CoffFormat : public FileFormat
{
	private:
		llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> fileBuffer;

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
		void loadSections();
		void loadSymbols();
		void loadRelocations();
		bool getRelocationMask(unsigned relType, std::vector<std::uint8_t> &mask);
		/// @}
	protected:
		llvm::object::COFFObjectFile *file; ///< parser of input COFF file
	public:
		CoffFormat(std::string pathToFile, LoadFlags loadFlags = LoadFlags::NONE);
		virtual ~CoffFormat() override;

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
		std::size_t getCoffSymbolTableOffset() const;
		std::size_t getNumberOfCoffSymbols() const;
		std::size_t getSizeOfStringTable() const;
		std::size_t getFileFlags() const;
		std::size_t getTimeStamp() const;
		bool is32BitArchitecture() const;
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
