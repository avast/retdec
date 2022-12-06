/**
 * @file include/retdec/fileformat/file_format/pe/pe_format_parser.h
 * @brief Definition of PeFormatParser class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_PE_FORMAT_PARSER_H
#define RETDEC_FILEFORMAT_PE_FORMAT_PARSER_H

#include "retdec/common/range.h"
#include "retdec/pelib/DebugDirectory.h"
#include "retdec/pelib/DelayImportDirectory.h"
#include "retdec/pelib/ExportDirectory.h"
#include "retdec/pelib/ImportDirectory.h"
#include "retdec/pelib/ResourceDirectory.h"
#include "retdec/utils/alignment.h"
#include "retdec/utils/string.h"
#include "retdec/fileformat/fftypes.h"
#include "retdec/pelib/PeFile.h"

namespace retdec {
namespace fileformat {

class FileFormat;

class PeFormatParser
{
	protected:

	const FileFormat *inputFile = nullptr;  ///< pointer to input file
	PeLib::PeFileT *peFile = nullptr;       ///< 32-bit PE file

	public:

	PeFormatParser(const FileFormat *fInputFile, PeLib::PeFileT *inputPeFile) : inputFile(fInputFile), peFile(inputPeFile)
	{}

	virtual ~PeFormatParser() = default;

	const PeLib::PeFileT* getPefile()
	{
		return peFile;
	}

	/// @name Detection methods
	/// @{

	std::uint32_t getPointerSize() const
	{
		return peFile->imageLoader().getPointerSize();
	}

	std::uint32_t getPeHeaderOffset() const
	{
		return peFile->imageLoader().getPeHeaderOffset();
	}

	std::uint32_t getImageBitability() const
	{
		return peFile->imageLoader().getImageBitability();
	}

	std::uint32_t getDeclaredNumberOfSections() const
	{
		return peFile->imageLoader().getFileHeader().NumberOfSections;
	}

	std::uint32_t getStoredNumberOfSections() const
	{
		return peFile->imageLoader().getNumberOfSections();
	}

	std::uint32_t getMachineType() const
	{
		return peFile->imageLoader().getMachine();
	}

	std::uint64_t getImageBaseAddress() const
	{
		return peFile->imageLoader().getImageBase();
	}

	std::uint32_t getCoffSymbolTableOffset() const
	{
		return peFile->imageLoader().getPointerToSymbolTable();
	}

	std::uint32_t getNumberOfCoffSymbols() const
	{
		return peFile->imageLoader().getNumberOfSymbols();
	}

	std::uint32_t getMajorLinkerVersion() const
	{
		return peFile->imageLoader().getOptionalHeader().MajorLinkerVersion;
	}

	std::uint32_t getMinorLinkerVersion() const
	{
		return peFile->imageLoader().getOptionalHeader().MinorLinkerVersion;
	}

	std::uint32_t getFileFlags() const
	{
		return peFile->imageLoader().getFileHeader().Characteristics;
	}

	std::uint32_t getTimeStamp() const
	{
		return peFile->imageLoader().getFileHeader().TimeDateStamp;
	}

	std::uint32_t getOptionalHeaderSize() const
	{
		return peFile->imageLoader().getFileHeader().SizeOfOptionalHeader;
	}

	bool isSizeOfHeaderMultipleOfFileAlignment() const
	{
		std::uint64_t remainder;
		return retdec::utils::isAligned(peFile->imageLoader().getSizeOfHeaders(),
										peFile->imageLoader().getFileAlignment(),
										remainder);
	}

	std::uint32_t getFileAlignment() const
	{
		return peFile->imageLoader().getFileAlignment();
	}

	std::uint32_t getSectionAlignment() const
	{
		return peFile->imageLoader().getSectionAlignment();
	}

	std::uint32_t getSizeOfHeaders() const
	{
		return peFile->imageLoader().getSizeOfHeaders();
	}

	std::uint32_t getSizeOfImage() const
	{
		return peFile->imageLoader().getSizeOfImage();
	}

	std::uint32_t getChecksum() const
	{
		return peFile->imageLoader().getOptionalHeader().CheckSum;
	}

	std::uint64_t getSizeOfStackReserve() const
	{
		return peFile->imageLoader().getOptionalHeader().SizeOfStackReserve;
	}

	std::uint64_t getSizeOfStackCommit() const
	{
		return peFile->imageLoader().getOptionalHeader().SizeOfStackCommit;
	}

	std::uint64_t getSizeOfHeapReserve() const
	{
		return peFile->imageLoader().getOptionalHeader().SizeOfHeapReserve;
	}

	std::uint64_t getSizeOfHeapCommit() const
	{
		return peFile->imageLoader().getOptionalHeader().SizeOfHeapCommit;
	}

	std::uint32_t getSizeOfPeSignature() const
	{
		return sizeof(std::uint32_t);
	}

	std::uint32_t getLoadedSizeOfNtHeaders() const
	{
		return peFile->imageLoader().getFileHeader().SizeOfOptionalHeader;
	}

	std::uint32_t getAllocatedSizeOfNtHeaders() const
	{
		return peFile->imageLoader().getFileHeader().SizeOfOptionalHeader;
	}

	std::uint32_t getDeclaredNumberOfDataDirectories() const
	{
		return peFile->imageLoader().getOptionalHeader().NumberOfRvaAndSizes;
	}

	std::uint32_t getStoredNumberOfDataDirectories() const
	{
		return peFile->imageLoader().getRealNumberOfDataDirectories();
	}

	std::uint32_t getNumberOfImportedLibraries() const
	{
		return peFile->impDir().getNumberOfFiles(false);
	}

	std::uint32_t getNumberOfDelayImportedLibraries() const
	{
		return peFile->delayImports().getNumberOfFiles();
	}

	bool isDll() const
	{
		return (peFile->imageLoader().getCharacteristics() & PeLib::PELIB_IMAGE_FILE_DLL);
	}

	bool getEpAddress(std::uint64_t & epAddress) const
	{
		std::uint64_t imageBase = peFile->imageLoader().getImageBase();
		std::uint32_t entryPoint = peFile->imageLoader().getOptionalHeader().AddressOfEntryPoint;

		// Do not report zero entry point on DLLs
		epAddress = imageBase + entryPoint;
		return (entryPoint != 0 || isDll() == false);
	}

	bool getEpOffset(std::uint64_t & epOffset) const
	{
		std::uint32_t entryPoint = peFile->imageLoader().getOptionalHeader().AddressOfEntryPoint;

		epOffset = peFile->imageLoader().getValidOffsetFromRva(entryPoint);
		return (entryPoint != 0 || isDll() == false) && (epOffset != UINT32_MAX);
	}

	bool getSectionType(const PeLib::PELIB_SECTION_HEADER * pSectionHeader, PeCoffSection::Type & secType) const
	{
		std::uint32_t Characteristics = pSectionHeader->Characteristics;

		if(Characteristics & (PeLib::PELIB_IMAGE_SCN_CNT_CODE | PeLib::PELIB_IMAGE_SCN_MEM_EXECUTE))
		{
			secType = PeCoffSection::Type::CODE;
		}
		else if(Characteristics & PeLib::PELIB_IMAGE_SCN_CNT_UNINITIALIZED_DATA)
		{
			secType = PeCoffSection::Type::BSS;
		}
		else if(Characteristics & PeLib::PELIB_IMAGE_SCN_MEM_DISCARDABLE && retdec::utils::startsWith(pSectionHeader->getName(), ".debug_"))
		{
			secType = PeCoffSection::Type::DEBUG;
		}
		else if(Characteristics & PeLib::PELIB_IMAGE_SCN_CNT_INITIALIZED_DATA)
		{
			secType = (!(Characteristics & PeLib::PELIB_IMAGE_SCN_MEM_WRITE)) ? PeCoffSection::Type::CONST_DATA : PeCoffSection::Type::DATA;
		}
		else if(Characteristics & PeLib::PELIB_IMAGE_SCN_LNK_INFO)
		{
			secType = PeCoffSection::Type::INFO;
		}
		else
		{
			secType = PeCoffSection::Type::UNDEFINED_SEC_SEG;
		}

		return true;
	}

	bool getSection(std::size_t secIndex, PeCoffSection &section) const
	{
		const PeLib::PELIB_SECTION_HEADER * pSectionHeader;
		PeCoffSection::Type sectionType;
		PeLib::ImageLoader & imageLoader = peFile->imageLoader();
		std::string sectionName;

		// Retrieve the section header. If the function returns nullptr, then there is no such section
		if((pSectionHeader = imageLoader.getSectionHeader(secIndex)) == nullptr)
			return false;
		if(!getSectionType(pSectionHeader, sectionType))
			return false;

		section.setName(pSectionHeader->getName());
		section.setType(sectionType);
		section.setIndex(secIndex);
		section.setOffset(imageLoader.getRealPointerToRawData(secIndex));
		section.setSizeInFile(imageLoader.getRealSizeOfRawData(secIndex));
		section.setSizeInMemory((pSectionHeader->VirtualSize != 0) ? pSectionHeader->VirtualSize : pSectionHeader->SizeOfRawData);
		section.setAddress(pSectionHeader->VirtualAddress ? imageLoader.getImageBase() + pSectionHeader->VirtualAddress : 0);
		section.setMemory(section.getAddress());
		section.setPeCoffFlags(pSectionHeader->Characteristics);
		section.load(inputFile);
		return true;
	}

	bool getDllFlags(std::uint64_t &dllFlags) const
	{
		dllFlags = peFile->imageLoader().getOptionalHeader().DllCharacteristics;
		return true;
	}

	bool getDataDirectoryRelative(std::uint64_t index, std::uint64_t &relAddr, std::uint64_t &size) const
	{
		relAddr = peFile->imageLoader().getDataDirRva(index);
		size = peFile->imageLoader().getDataDirSize(index);
		return (relAddr != 0);
	}

	bool getComDirectoryRelative(std::uint64_t &relAddr, std::uint64_t &size) const
	{
		relAddr = peFile->imageLoader().getComDirRva();
		size = peFile->imageLoader().getComDirSize();
		return (relAddr != 0);
	}

	bool getDataDirectoryAbsolute(std::uint64_t index, std::uint64_t &absAddr, std::uint64_t &size) const
	{
		if(getDataDirectoryRelative(index, absAddr, size))
		{
			absAddr += peFile->imageLoader().getImageBase();
			return true;
		}

		return false;
	}

	bool getImportedLibraryFileName(std::uint32_t index, std::string &fileName) const
	{
		const auto & imports = peFile->impDir();

		if(index >= imports.getNumberOfFiles(false))
			return false;

		fileName = imports.getFileName(index, false);
		return true;
	}

	bool getDelayImportedLibraryFileName(unsigned long long index, std::string &fileName) const
	{
		const auto & delayImports = peFile->delayImports();

		if(index >= delayImports.getNumberOfFiles())
			return false;

		fileName = delayImports.getFile(index)->Name;
		return true;
	}

	std::unique_ptr<PeImport> getImport(std::size_t fileIndex, std::size_t importIndex) const
	{
		const PeLib::ImportDirectory & peImports = peFile->impDir();
		const auto imageBase = peFile->imageLoader().getImageBase();
		const auto bits = peFile->imageLoader().getImageBitability();
		std::string importName;
		std::uint64_t addressMask = (bits == 0x20) ? 0xFFFFFFFF : 0xFFFFFFFFFFFFFFFF;
		std::uint32_t ordinalNumber = 0;
		std::uint32_t patchRva = 0;
		std::uint16_t importHint = 0;
		bool isImportByOrdinal = false;

		if(peImports.getImportedFunction(fileIndex, importIndex, importName, importHint, ordinalNumber, patchRva, isImportByOrdinal, false))
		{
			auto import = std::make_unique<PeImport>(PeImportFlag::None);

			if(isImportByOrdinal)
			{
				import->setOrdinalNumber(ordinalNumber);
			}

			// Note: Even when the function is imported by ordinal, there can be name
			// Example: WS2_32.dll!@115 -> WSAStartup
			import->setName(importName);

			import->setLibraryIndex(fileIndex);

			// Don't allow address overflow for samples with high image bases
			// (342EE6CCB04AB0194275360EE6F752007B9F0CE5420203A41C8C9B5BAC7626DD)
			import->setAddress((imageBase + patchRva) & addressMask);
			return import;
		}

		// Out of range
		return nullptr;
	}

	std::unique_ptr<PeImport> getDelayImport(unsigned long long fileIndex, unsigned long long importIndex) const
	{
		const PeLib::DelayImportDirectory & delayImports = peFile->delayImports();
		const auto *library = delayImports.getFile(fileIndex);

		if(!library)
		{
			return nullptr;
		}

		const auto *function = library->getFunction(importIndex);
		if(!function)
		{
			return nullptr;
		}

		auto import = std::make_unique<PeImport>(PeImportFlag::Delayed);
		import->setName(function->fname);
		import->setAddress(peFile->imageLoader().getImageBase() + function->address);
		import->setLibraryIndex(fileIndex);
		import->invalidateOrdinalNumber();
		if(library->ordinalNumbersAreValid() && function->hint != 0)
		{
			import->setOrdinalNumber(function->hint);
		}

		return import;
	}

	std::uint32_t getNumberOfExportedFunctions() const
	{
		return peFile->expDir().calcNumberOfFunctions();
	}

	bool getExportedFunction(unsigned long long index, Export& exportedFunction) const
	{
		const PeLib::ExportDirectory & exports = peFile->expDir();
		const PeLib::ImageLoader & imageLoader = peFile->imageLoader();

		if (index >= exports.calcNumberOfFunctions())
		{
			return false;
		}

		exportedFunction.setAddress(exports.getAddressOfFunction(index) + imageLoader.getImageBase());
		exportedFunction.setOrdinalNumber(exports.getFunctionOrdinal(index));
		exportedFunction.setName(exports.getFunctionName(index));
		return true;
	}

	std::uint32_t getNumberOfDebugEntries() const
	{
		return peFile->debugDir().calcNumberOfEntries();
	}

	bool getDebugEntryData(unsigned long long index, std::vector<std::uint8_t>& data) const
	{
		const PeLib::DebugDirectory & debug = peFile->debugDir();

		if (index < debug.calcNumberOfEntries())
		{
			data = debug.getData(index);
			return true;
		}

		return false;
	}

	bool getDebugEntryTimeDateStamp(unsigned long long index, unsigned long long& timeDateStamp) const
	{
		const PeLib::DebugDirectory & debug = peFile->debugDir();

		if (index < debug.calcNumberOfEntries())
		{
			timeDateStamp = debug.getTimeDateStamp(index);
			return true;
		}

		return false;
	}

	bool getDebugEntryPointerToRawData(unsigned long long index, unsigned long long& pointerToRawData) const
	{
		const PeLib::DebugDirectory & debug = peFile->debugDir();

		if (index < debug.calcNumberOfEntries())
		{
			pointerToRawData = debug.getPointerToRawData(index);
			return true;
		}

		return false;
	}

	std::uint32_t getResourceDirectoryOffset() const
	{
		return peFile->resDir().getOffset();
	}

	const PeLib::ResourceNode* getResourceTreeRoot() const
	{
		return peFile->resDir().getRoot();
	}

	std::uint64_t getTlsStartAddressOfRawData() const
	{
		return peFile->tlsDir().getStartAddressOfRawData();
	}

	std::uint64_t getTlsEndAddressOfRawData() const
	{
		return peFile->tlsDir().getEndAddressOfRawData();
	}

	std::uint64_t getTlsAddressOfIndex() const
	{
		return peFile->tlsDir().getAddressOfIndex();
	}

	const std::vector<uint64_t> & getCallbacks() const
	{
		return peFile->tlsDir().getCallbacks();
	}

	std::uint64_t getTlsAddressOfCallBacks() const
	{
		return peFile->tlsDir().getAddressOfCallBacks();
	}

	std::uint32_t getTlsSizeOfZeroFill() const
	{
		return peFile->tlsDir().getSizeOfZeroFill();
	}

	std::uint32_t getTlsCharacteristics() const
	{
		return peFile->tlsDir().getCharacteristics();
	}

	std::unique_ptr<CLRHeader> getClrHeader() const
	{
		const auto & comHeader = peFile->comDir();
		auto clrHeader = std::make_unique<CLRHeader>();

		clrHeader->setHeaderSize(comHeader.getSizeOfHeader());
		clrHeader->setMajorRuntimeVersion(comHeader.getMajorRuntimeVersion());
		clrHeader->setMinorRuntimeVersion(comHeader.getMinorRuntimeVersion());
		clrHeader->setMetadataDirectoryAddress(comHeader.getMetaDataVa());
		clrHeader->setMetadataDirectorySize(comHeader.getMetaDataSize());
		clrHeader->setFlags(comHeader.getFlags());
		clrHeader->setEntryPointToken(comHeader.getEntryPointToken());
		clrHeader->setResourcesAddress(comHeader.getResourcesVa());
		clrHeader->setResourcesSize(comHeader.getResourcesSize());
		clrHeader->setStrongNameSignatureAddress(comHeader.getStrongNameSignatureVa());
		clrHeader->setStrongNameSignatureSize(comHeader.getStrongNameSignatureSize());
		clrHeader->setCodeManagerTableAddress(comHeader.getCodeManagerTableVa());
		clrHeader->setCodeManagerTableSize(comHeader.getCodeManagerTableSize());
		clrHeader->setVTableFixupsDirectoryAddress(comHeader.getVTableFixupsVa());
		clrHeader->setVTableFixupsDirectorySize(comHeader.getVTableFixupsSize());
		clrHeader->setExportAddressTableAddress(comHeader.getExportAddressTableJumpsVa());
		clrHeader->setExportAddressTableSize(comHeader.getExportAddressTableJumpsSize());
		clrHeader->setPrecompileHeaderAddress(comHeader.getManagedNativeHeaderVa());
		clrHeader->setPrecompileHeaderSize(comHeader.getManagedNativeHeaderSize());
		return clrHeader;
	}

	std::uint32_t getNumberOfRelocations() const
	{
		return peFile->relocDir().calcNumberOfRelocations();
	}

	std::uint32_t getNumberOfRelocationData(std::uint32_t index) const
	{
		return peFile->relocDir().calcNumberOfRelocationData(index);
	}

	std::uint64_t getChecksumFileOffset() const
	{
		return peFile->imageLoader().getChecksumFileOffset();
	}

	std::uint64_t getSecurityDirFileOffset() const
	{
		return peFile->imageLoader().getSecurityDirFileOffset();
	}

	std::uint32_t getSecurityDirRva() const
	{
		return peFile->imageLoader().getDataDirRva(PeLib::PELIB_IMAGE_DIRECTORY_ENTRY_SECURITY);
	}

	std::uint32_t getSecurityDirSize() const
	{
		return peFile->imageLoader().getDataDirSize(PeLib::PELIB_IMAGE_DIRECTORY_ENTRY_SECURITY);
	}

	const PeLib::ImportDirectory& getImportDirectory() const
	{
		return peFile->impDir();
	}

	const PeLib::DebugDirectory& getDebugDirectory() const
	{
		return peFile->debugDir();
	}

	const PeLib::ResourceDirectory& getResourceDirectory() const
	{
		return peFile->resDir();
	}

	const PeLib::ExportDirectory& getExportDirectory() const
	{
		return peFile->expDir();
	}

	const PeLib::DelayImportDirectory& getDelayDirectory() const
	{
		return peFile->delayImports();
	}

	retdec::common::RangeContainer<std::uint64_t> getImportDirectoryOccupiedAddresses() const
	{
		retdec::common::RangeContainer<std::uint64_t> result;
		const auto & peImports = peFile->impDir();

		for (const auto& addresses : peImports.getOccupiedAddresses())
		{
			try
			{
				result.insert(addresses.first, addresses.second);
			}
			catch (const retdec::common::InvalidRangeException&)
			{
				continue;
			}
		}

		return result;
	}

	retdec::common::RangeContainer<std::uint64_t> getExportDirectoryOccupiedAddresses() const
	{
		retdec::common::RangeContainer<std::uint64_t> result;
		const auto & peExports = peFile->expDir();

		for (const auto& addresses : peExports.getOccupiedAddresses())
		{
			try
			{
				result.insert(addresses.first, addresses.second);
			}
			catch (const retdec::common::InvalidRangeException&)
			{
				continue;
			}
		}

		return result;
	}

	retdec::common::RangeContainer<std::uint64_t> getDebugDirectoryOccupiedAddresses() const
	{
		retdec::common::RangeContainer<std::uint64_t> result;
		const auto & peDebug = peFile->debugDir();

		for (const auto& addresses : peDebug.getOccupiedAddresses())
		{
			try
			{
				result.insert(addresses.first, addresses.second);
			}
			catch (const retdec::common::InvalidRangeException&)
			{
				continue;
			}
		}

		return result;
	}

	retdec::common::RangeContainer<std::uint64_t> getResourceDirectoryOccupiedAddresses() const
	{
		retdec::common::RangeContainer<std::uint64_t> result;
		const auto & peResources = peFile->resDir();

		for (const auto& addresses : peResources.getOccupiedAddresses())
		{
			try
			{
				result.insert(addresses.first, addresses.second);
			}
			catch (const retdec::common::InvalidRangeException&)
			{
				continue;
			}
		}

		return result;
	}

};

} // namespace fileformat
} // namespace retdec

#endif
