/**
 * @file include/retdec/fileformat/file_format/macho/macho_format.h
 * @brief Definition of MachOFormat class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_FILE_FORMAT_MACHO_MACHO_FORMAT_H
#define RETDEC_FILEFORMAT_FILE_FORMAT_MACHO_MACHO_FORMAT_H

#include <cstdint>

#include <llvm/Object/MachO.h>
#include <llvm/Object/MachOUniversal.h>
#include <llvm/Support/MachO.h>

#include "retdec/fileformat/file_format/file_format.h"

namespace retdec {
namespace fileformat {

/**
 * MachOFormat - wrapper for parsing MachO files
 */
class MachOFormat : public FileFormat
{
	private:
		bool isLittle = true;                                          ///< @c true if file is little endian
		bool is32 = true;                                              ///< @c true if address size is 32 bits
		bool isFat = false;                                            ///< @c true if file is universal binary
		bool isDyld = false;                                           ///< @c true if file has LC_DYLD_INFO command
		bool isStaticLib = false;                                      ///< @c true if file static library signature is detected
		bool hasEntryPoint = false;                                    ///< @c true if file has LC_MAIN or LC_UNIXTHREAD command
		unsigned long long entryPointAddr = 0;                         ///< entry point address
		unsigned long long entryPointOffset = 0;                       ///< entry point offset
		std::uint32_t chosenArchOffset = 0;                            ///< offset of chosen architecture from universal binary
		std::uint32_t chosenArchSize = 0;                              ///< size of chosen architecture from universal binary
		std::vector<std::uint8_t> chosenArchBytes;                     ///< bytes of chosen architecture from universal binary
		std::size_t sectionCounter = 0;                                ///< number of segment commands found
		std::size_t segmentCounter = 0;                                ///< number of section commands found
		std::vector<MachOSymbol> symbols;                              ///< temporary symbol representation
		std::vector<unsigned long long> indirectTable;                 ///< indirect table for import addresses
		llvm::MachO::mach_header header32;                             ///< 32 bit Mach-O header
		llvm::MachO::mach_header_64 header64;                          ///< 64 bit Mach-O header
		llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> fileBuffer; ///< LLVM buffer of input file

		/// @name Auxiliary initialization methods
		/// @{
		void setWidthAndEndianness();
		bool chooseArchitecture(const llvm::object::MachOUniversalBinary::object_iterator &itr);
		bool constructMachO();
		bool constructFatMachO();
		/// @}

		/// @name Initialization methods
		/// @{
		void initStructures();
		/// @}

		/// @name Sections and segments commands methods
		/// @{
		std::string getSecSegName(const char *secSegName) const;
		SecSeg::Type getSegmentType(const char *segName) const;
		SecSeg::Type getSectionType(std::uint32_t flags, const std::string &name) const;
		std::vector<std::uint8_t> createRelocationMask(unsigned length) const;
		void handleScatteredRelocation(std::uint32_t firstDword, RelocationTable *tabPtr);
		void handleRelocation(std::uint32_t firstDword, std::uint32_t secondDword, RelocationTable *tabPtr);
		void loadSectionRelocations(std::size_t offset, std::size_t count);
		template<typename T> void loadSection(const T &section);
		template<typename T> Segment* loadSegment(const T &segment);
		void segmentCommand(const llvm::object::MachOObjectFile::LoadCommandInfo &commandInfo);
		void segment64Command(const llvm::object::MachOObjectFile::LoadCommandInfo &commandInfo);
		/// @}

		/// @name Entry point commands methods
		/// @{
		void entryPointCommand(const llvm::object::MachOObjectFile::LoadCommandInfo &commandInfo);
		void oldEntryPointCommand(const llvm::object::MachOObjectFile::LoadCommandInfo &commandInfo);
		/// @}

		/// @name Symbols & Imports & Exports commands methods
		/// @{
		void loadDylibCommand(const llvm::object::MachOObjectFile::LoadCommandInfo &commandInfo);
		void symtabCommand();
		MachOSection* getLazySymbolsSection() const;
		MachOSection* getNonLazySymbolsSection() const;
		void getImportsFromSection(const MachOSection *secPtr);
		void parseIndirectTable(std::uint32_t offset, std::uint32_t size);
		void dySymtabCommand();
		void dyldInfoCommand(const llvm::object::MachOObjectFile::LoadCommandInfo &commandInfo);
		std::unique_ptr<Import> getImportFromBindEntry(const llvm::object::MachOBindEntry &input);
		/// @}

		/// @name Load commands methods
		/// @{
		std::uint32_t getNumberOfCommands() const;
		std::uint32_t getFirstCommandOffset() const;
		void loadCommands();
		void dumpCommands(std::ostream &outStream);
		/// @}

		/// @name Auxiliary methods
		/// @{
		unsigned long long get32Bit(const char *ptr) const;
		unsigned long long get64Bit(const char *ptr) const;
		unsigned long long offsetToAddress(unsigned long long offset) const;
		Architecture getTargetArchitecture(std::uint32_t cpuType) const;
		std::vector<std::string> getMachOUniversalArchitectures() const;
		const char* getBufferStart() const;
		void clearCommands();
		/// @}
	protected:
		std::unique_ptr<llvm::object::MachOObjectFile> file;         ///< parser of input file
		std::unique_ptr<llvm::object::MachOUniversalBinary> fatFile; ///< parser of universal binary
	public:
		MachOFormat(std::string pathToFile, LoadFlags loadFlags = LoadFlags::NONE);
		virtual ~MachOFormat() override;

		/// @name Byte value storage methods
		/// @{
		virtual retdec::utils::Endianness getEndianness() const override;
		virtual std::size_t getBytesPerWord() const override;
		virtual bool hasMixedEndianForDouble() const override;
		/// @}

		/// @name Virtual detection methods
		/// @{
		virtual std::string getFileFormatName() const override;
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
		virtual std::size_t initSectionTableHashOffsets() override;
		virtual std::size_t getSectionTableOffset() const override;
		virtual std::size_t getSectionTableEntrySize() const override;
		virtual std::size_t getSegmentTableOffset() const override;
		virtual std::size_t getSegmentTableEntrySize() const override;
		/// @}

		/// @name Detection methods
		/// @{
		bool is32Bit() const;
		bool isFatBinary() const;
		bool isStaticLibrary() const;
		bool getTargetOs(std::string &name, std::string &version) const;
		bool getEncryptionInfo(unsigned long &off, unsigned long &size, unsigned long &id);
		std::uint32_t getFileType() const;
		std::uint32_t getSizeOfCommands() const;
		/// @}

		/// @name Universal binary architecture switching
		/// @{
		bool chooseArchitecture(std::uint32_t cpuType);
		bool chooseArchitectureAtIndex(std::uint32_t index);
		std::uint32_t getChosenArchitectureOffset() const;
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
