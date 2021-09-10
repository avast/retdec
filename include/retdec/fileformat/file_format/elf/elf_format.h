/**
 * @file include/retdec/fileformat/file_format/elf/elf_format.h
 * @brief Definition of ElfFormat class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_FILE_FORMAT_ELF_ELF_FORMAT_H
#define RETDEC_FILEFORMAT_FILE_FORMAT_ELF_ELF_FORMAT_H

#include <unordered_map>

#include <elfio/elfio.hpp>

#include "retdec/fileformat/file_format/file_format.h"
#include "retdec/fileformat/types/note_section/elf_notes.h"
#include "retdec/fileformat/types/import_table/elf_import_table.h"

namespace retdec {
namespace fileformat {

/**
 * ElfFormat - wrapper for parsing ELF files
 */
class ElfFormat : public FileFormat
{
	private:
		std::vector<std::string> telfhashSymbols;
		/// flag if we already loaded symbols from SHT_DYNSYM
		bool telfhashDynsym = false;
		std::string telfhash;

		/**
		 * Description of ELF relocation table
		 */
		struct RelocationTableInfo
		{
			/// start address of relocation table
			unsigned long long address = 0;
			/// size of table
			unsigned long long size = 0;
			/// size of one entry in table
			unsigned long long entrySize = 0;
			/// type of relocations (SHT_REL or SHT_RELA)
			unsigned long long type = SHT_NULL;
			/// associated with Procedure Linkage Table.
			bool plt = false;
		};

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
		ELFIO::section* addStringTable(ELFIO::section *dynamicSection, const DynamicTable &table);
		ELFIO::section* addSymbolTable(ELFIO::section *dynamicSection, const DynamicTable &table, ELFIO::section *stringTable);
		ELFIO::section* addRelocationTable(ELFIO::section *dynamicSection, const RelocationTableInfo &info, ELFIO::section *symbolTable);
		ELFIO::section* addRelRelocationTable(ELFIO::section *dynamicSection, const DynamicTable &table, ELFIO::section *symbolTable);
		ELFIO::section* addRelaRelocationTable(ELFIO::section *dynamicSection, const DynamicTable &table, ELFIO::section *symbolTable);
		ELFIO::section* addPltRelocationTable(ELFIO::section *dynamicSection, const DynamicTable &table, ELFIO::section *symbolTable);
		ELFIO::section* addGlobalOffsetTable(ELFIO::section *dynamicSection, const DynamicTable &table);
		ELFIO::Elf_Half fixSymbolLink(ELFIO::Elf_Half symbolLink, ELFIO::Elf64_Addr symbolValue);
		bool getRelocationMask(unsigned relType, std::vector<std::uint8_t> &mask);
		void loadRelocations(const ELFIO::elfio *file, const ELFIO::section *symbolTable, std::unordered_multimap<std::string, unsigned long long> &nameAddressMap);
		void loadSymbols(const ELFIO::elfio *file, const ELFIO::symbol_section_accessor *elfSymbolTable, const ELFIO::section *elfSection);
		void loadSymbols(const SymbolTable &oldTab, const DynamicTable &dynTab, ELFIO::section &got);
		void loadDynamicTable(DynamicTable &table, const ELFIO::dynamic_section_accessor *elfDynamicTable);
		DynamicTable* loadDynamicTable(
				const ELFIO::dynamic_section_accessor *elfDynamicTable,
				const ELFIO::section *sec);
		void loadSections();
		void loadSegments();
		void loadDynamicSegmentSection();
		void loadInfoFromDynamicTables(DynamicTable &dynTab, ELFIO::section *sec);
		void loadInfoFromDynamicSegment();
		void loadNoteSecSeg(ElfNoteSecSeg &noteSecSegs) const;
		void loadNotes();
		void loadCoreFileMap(std::size_t offset, std::size_t size);
		void loadCorePrStat(std::size_t offset, std::size_t size);
		void loadCorePrPsInfo(std::size_t offset, std::size_t size);
		void loadCoreAuxvInfo(std::size_t offset, std::size_t size);
		void loadCoreInfo();
		void loadTelfhash();
		/// @}
	protected:
		int elfClass;        ///< class of input ELF file
		ELFIO::elfio reader; ///< parser of input ELF file
		ELFIO::elfio writer; ///< parser of auxiliary ELF object which is needed for fixing representation of input file

		/// Offsets of already read symbol tables.
		std::set<ELFIO::Elf64_Off> symtabOffsets;
		/// Addresses of already read symbol tables.
		std::set<ELFIO::Elf64_Addr> symtabAddresses;
	public:
		ElfFormat(std::string pathToFile, LoadFlags loadFlags = LoadFlags::NONE);
		ElfFormat(std::istream &inputStream, LoadFlags loadFlags = LoadFlags::NONE);
		ElfFormat(const std::uint8_t *data, std::size_t size, LoadFlags loadFlags = LoadFlags::NONE);

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
		std::size_t getTypeOfFile() const;
		std::size_t getFileVersion() const;
		std::size_t getFileHeaderVersion() const;
		std::size_t getFileHeaderSize() const;
		std::size_t getFileFlags() const;
		std::size_t getOsOrAbi() const;
		std::size_t getOsOrAbiVersion() const;
		std::size_t getSectionTableSize() const;
		std::size_t getSegmentTableSize() const;
		const std::string& getTelfhash() const;
		int getElfClass() const;
		bool isWiiPowerPc() const;
		/// @}

		/// @name Other methods
		/// @{
		unsigned long long getBaseOffset() const;
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
