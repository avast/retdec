/**
 * @file src/pelib/ImageLoader.cpp
 * @brief Implementation of image
 * @copyright (c) 2020 Avast Software, licensed under the MIT license
 */

#include <cstdint>
#include <iostream>
#include <fstream>

#include "retdec/pelib/ImageLoader.h"

//-----------------------------------------------------------------------------
// Static class variables

std::uint8_t PeLib::ImageLoader::ImageProtectionArray[16] =
{
	PELIB_PAGE_NOACCESS,
	PELIB_PAGE_EXECUTE,
	PELIB_PAGE_READONLY,
	PELIB_PAGE_EXECUTE_READ,
	PELIB_PAGE_WRITECOPY,
	PELIB_PAGE_EXECUTE_WRITECOPY,
	PELIB_PAGE_WRITECOPY,
	PELIB_PAGE_EXECUTE_WRITECOPY,
	PELIB_PAGE_NOACCESS,
	PELIB_PAGE_EXECUTE,
	PELIB_PAGE_READONLY,
	PELIB_PAGE_EXECUTE_READ,
	PELIB_PAGE_READWRITE,
	PELIB_PAGE_EXECUTE_READWRITE,
	PELIB_PAGE_READWRITE,
	PELIB_PAGE_EXECUTE_READWRITE
};

//-----------------------------------------------------------------------------
// Constructor and destructor

PeLib::ImageLoader::ImageLoader(std::uint32_t versionInfo)
{
	memset(&dosHeader, 0, sizeof(PELIB_IMAGE_DOS_HEADER));
	memset(&fileHeader, 0, sizeof(PELIB_IMAGE_FILE_HEADER));
	memset(&optionalHeader, 0, sizeof(PELIB_IMAGE_OPTIONAL_HEADER));
	checkSumFileOffset = 0;
	securityDirFileOffset = 0;
	realNumberOfRvaAndSizes = 0;
	ntSignature = 0;
	ldrError = LDR_ERROR_NONE;

	// By default, set the most benevolent settings
	ssiImageAlignment32 = PELIB_PAGE_SIZE;
	sizeofImageMustMatch = false;
	ntHeadersSizeCheck = false;
	architectureSpecificChecks = false;
	maxSectionCount = 255;
	is64BitWindows = (versionInfo & BuildNumber64Bit) ? true : false;
	windowsBuildNumber = (versionInfo & BuildNumberMask);
	headerSizeCheck = false;
	loadArmImages = true;
	loadArm64Images = true;
	loadItaniumImages = true;
	forceIntegrityCheckEnabled = false;
	forceIntegrityCheckCertificate = false;
	checkNonLegacyDllCharacteristics = false;
	checkImagePostMapping = false;

	// If the caller specified a Windows build, then we configure version-specific behavior
	if(windowsBuildNumber != 0)
	{
		// Single-section images are aligned to zector in Windows XP
		// Note that Windows 8-10 do this somewhat randomly; the same image is mapped differently when in different folders
		ssiImageAlignment32 = (BuildNumberXP <= windowsBuildNumber && windowsBuildNumber < BuildNumberVista) ? PELIB_SECTOR_SIZE : 1;

		// Max section count is smaller in Windows XP
		maxSectionCount = (BuildNumberXP <= windowsBuildNumber && windowsBuildNumber < BuildNumberVista) ? PE_MAX_SECTION_COUNT_XP : PE_MAX_SECTION_COUNT_7;

		// Weird check in Windows XP: See checkForSectionTablesWithinHeader
		headerSizeCheck = (BuildNumberXP <= windowsBuildNumber && windowsBuildNumber < BuildNumberVista);

		// Beginning with Windows Vista, the file size must be >= sizeof(IMAGE_NT_HEADERS)
		ntHeadersSizeCheck = (BuildNumberVista <= windowsBuildNumber);

		// Beginning with Vista, IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY actually does something
		forceIntegrityCheckEnabled = (windowsBuildNumber >= BuildNumberVista);
		forceIntegrityCheckCertificate = (windowsBuildNumber >= BuildNumber8);

		// Beginning with Windows 8, ARM images can also be loader
		loadArmImages = (windowsBuildNumber >= BuildNumber8);

		// ARM64 images are only loaded from Windows 10 up
		loadArm64Images = (windowsBuildNumber >= BuildNumber10);

		// From Windows XP to Windows 7, 64-bit Windows will load Itanium images
		if(is64BitWindows && windowsBuildNumber >= BuildNumber8)
			loadItaniumImages = false;

		// Windows 8+ perform check for bad app container apps
		architectureSpecificChecks = (windowsBuildNumber >= BuildNumber8);

		// After build 17134, SizeOfImage can also be greater than virtual end of the last section
		sizeofImageMustMatch = (windowsBuildNumber <= 17134);

		// Since build 17134, Load Config is checked within nt!MiRelocateImage
		checkImagePostMapping = (windowsBuildNumber >= 17134);

		// Since build 18362, extra checks are performed on non-intel platforms
		checkNonLegacyDllCharacteristics = (windowsBuildNumber >= 18362);

		// Since build 21996, single-section images only contain data up to the image size
		alignSingleSectionImagesToPage = !(windowsBuildNumber >= 21996);
	}
}

//-----------------------------------------------------------------------------
// Public functions

bool PeLib::ImageLoader::relocateImage(std::uint64_t newImageBase)
{
	std::uint32_t VirtualAddress;
	std::uint32_t Size;
	bool result = true;

	// Only relocate the image if the image base is different
	if(newImageBase != optionalHeader.ImageBase)
	{
		// If the image was not properly mapped, don't even try.
		if(pages.size() == 0)
			return false;

		// If relocations are stripped, do nothing
		if(fileHeader.Characteristics & PELIB_IMAGE_FILE_RELOCS_STRIPPED)
			return false;

		// Don't relocate 32-bit images to an address greater than 32bits
		if(optionalHeader.Magic == PELIB_IMAGE_NT_OPTIONAL_HDR32_MAGIC && (newImageBase >> 32))
			return false;

		// Change the image base in the header. This happens even if the image does not have relocations.
		// Sample: f5bae114007e5f5eb2a7e41fbd7cf4062b21e1a33e0648a07eb1e25c106bd7eb
		writeNewImageBase(newImageBase);

		// The image must have relocation directory
		if(optionalHeader.NumberOfRvaAndSizes <= PELIB_IMAGE_DIRECTORY_ENTRY_BASERELOC)
			return false;

		// The relocation data directory must be valid
		VirtualAddress = optionalHeader.DataDirectory[PELIB_IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
		Size = optionalHeader.DataDirectory[PELIB_IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
		if(VirtualAddress == 0 || Size == 0)
			return false;

		// Do not relocate images with weird or invalid relocation table
		if(!isValidImageBlock(VirtualAddress, Size))
			return false;

		// Perform relocations
		result = processImageRelocations(optionalHeader.ImageBase, newImageBase, VirtualAddress, Size);
	}

	return result;
}

std::uint32_t PeLib::ImageLoader::readImage(
	void * buffer,
	std::uint32_t rva,
	std::uint32_t bytesToRead)
{
	// If the image was properly mapped, perform an image-read operation
	if(rawFileData.size() == 0)
	   return readWriteImage(buffer, rva, bytesToRead, readFromPage);

	// If the image loader was unable to map the image, we provide fallback method
	// by translating the RVA to file offset. Note that in some cases, this methos
	// may produce unwanted results.
	// Example: If export directory is at the end of section, it will be padded by zeros by the loader,
	// but in the on-disk version, next section will follow.
	return readWriteImageFile(buffer, rva, bytesToRead, true);
}

std::uint32_t PeLib::ImageLoader::writeImage(
	void * buffer,
	std::uint32_t rva,
	std::uint32_t bytesToRead)
{
	// If the image was properly mapped, perform an image-read operation
	if(rawFileData.size() == 0)
		return readWriteImage(buffer, rva, bytesToRead, writeToPage);

	// If the image loader was unable to map the image, we provide fallback method
	// by translating the RVA to file offset.
	return readWriteImageFile(buffer, rva, bytesToRead, false);
}

std::uint32_t PeLib::ImageLoader::stringLength(
	std::uint32_t rva,
	std::uint32_t maxLength) const
{
	std::uint32_t rvaBegin = rva;
	std::uint32_t rvaEnd = rva + maxLength;
	std::uint32_t length = 0;

	// Is the image mapped OK?
	if(pages.size())
	{
		// Check the last possible address where we read
		if(rvaEnd > getSizeOfImageAligned())
			rvaEnd = getSizeOfImageAligned();

		// Is the offset within the image?
		if(rva < rvaEnd)
		{
			std::size_t pageIndex = rva / PELIB_PAGE_SIZE;

			// The page index must be in range
			if(pageIndex < pages.size())
			{
				while(rva < rvaEnd)
				{
					const PELIB_FILE_PAGE & page = pages[pageIndex];
					const std::uint8_t * dataBegin;
					const std::uint8_t * dataPtr;
					std::uint32_t rvaEndPage = (pageIndex + 1) * PELIB_PAGE_SIZE;

					// If zero page, means this is a zeroed page. This is the end of the string.
					if(page.buffer.empty())
						break;
					dataBegin = dataPtr = page.buffer.data() + (rva & (PELIB_PAGE_SIZE - 1));

					// Perhaps the last page loaded?
					if(rvaEndPage > rvaEnd)
						rvaEndPage = rvaEnd;

					// Try to find the zero byte on the page
					dataPtr = (const std::uint8_t *)memchr(dataPtr, 0, (rvaEndPage - rva));
					if(dataPtr != nullptr)
						return rva + (dataPtr - dataBegin) - rvaBegin;
					rva = rvaEndPage;

					// Move pointers
					pageIndex++;
				}
			}
		}

		// Return the length of the string
		length = (rva - rvaBegin);
	}
	else
	{
		// Recalc the file offset to RVA
		if((rva = getFileOffsetFromRva(rva)) < rawFileData.size())
		{
			const std::uint8_t * stringPtr = rawFileData.data() + rva;
			const std::uint8_t * stringEnd;

			length = rawFileData.size() - rva;

			stringEnd = (const std::uint8_t *)memchr(stringPtr, 0, length);
			if(stringEnd != nullptr)
				length = stringEnd - stringPtr;
		}
	}

	return length;
}

std::uint32_t PeLib::ImageLoader::readString(
	std::string & str,
	std::uint32_t rva,
	std::uint32_t maxLength)
{
	// Check the length of the string at the rva
	std::uint32_t length = stringLength(rva, maxLength);

	// Allocate needeed size in the string
	str.resize(length);

	// Read the string from the image
	readImage((void *)str.data(), rva, length);
	return length;
}

std::uint32_t PeLib::ImageLoader::readPointer(
	std::uint32_t rva,
	std::uint64_t & pointerValue)
{
	std::uint32_t bytesRead = 0;

	switch(getImageBitability())
	{
		case 64:
			if(readImage(&pointerValue, rva, sizeof(std::uint64_t)) == sizeof(std::uint64_t))
				return sizeof(std::uint64_t);
			break;

		case 32:
		{
			std::uint32_t pointerValue32 = 0;

			bytesRead = readImage(&pointerValue32, rva, sizeof(std::uint32_t));
			if(bytesRead == sizeof(std::uint32_t))
			{
				pointerValue = pointerValue32;
				return sizeof(std::uint32_t);
			}

			break;
		}
	}

	return 0;
}

std::uint32_t PeLib::ImageLoader::getPointerSize()  const
{
	return getImageBitability() / 8;
}

std::uint32_t PeLib::ImageLoader::readStringRc(
	std::string & str,
	std::uint32_t rva)
{
	std::vector<std::uint16_t> wideString;
	std::uint32_t bytesToRead;
	std::uint32_t charsRead;
	std::uint16_t length = 0;

	// Read the length of the string from the image
	readImage(&length, rva, sizeof(std::uint16_t));
	rva += sizeof(std::uint16_t);

	// Allocate enough space
	bytesToRead = length * sizeof(std::uint16_t);
	wideString.resize(length);

	// Read the entire string from the image
	charsRead = readImage(wideString.data(), rva, bytesToRead) / sizeof(std::uint16_t);
	str.resize(charsRead);

	// Convert the UTF-16 string to ANSI. Note that this is not the proper way to do it,
	// but it's the same way how retdec-fileinfo.exe always did it, so we keep it that way
	for(std::uint32_t i = 0; i < charsRead; i++)
		str[i] = wideString[i];
	return charsRead;
}

std::uint32_t PeLib::ImageLoader::readStringRaw(
	ByteBuffer & fileData,
	std::string & str,
	std::size_t offset,
	std::size_t maxLength,
	bool mustBePrintable,
	bool mustNotBeTooLong)
{
	std::size_t length = 0;

	if(offset < fileData.size())
	{
		std::uint8_t * stringBegin = fileData.data() + offset;
		std::uint8_t * stringEnd;

		// Make sure we won't read past the end of the buffer
		if((offset + maxLength) > fileData.size())
			maxLength = fileData.size() - offset;

		// Get the length of the string. Do not go beyond the maximum length
		// Note that there is no guaratee that the string is zero terminated, so can't use strlen
		// retdec-regression-tests\tools\fileinfo\bugs\issue-451-strange-section-names\4383fe67fec6ea6e44d2c7d075b9693610817edc68e8b2a76b2246b53b9186a1-unpacked
		stringEnd = (std::uint8_t *)memchr(stringBegin, 0, maxLength);
		if(stringEnd == nullptr)
		{
			// No zero terminator means that the string is limited by max length
			if(mustNotBeTooLong)
				return 0;
			stringEnd = stringBegin + maxLength;
		}

		// Copy the string
		length = stringEnd - stringBegin;
		str.resize(length);
		memcpy(const_cast<char *>(str.data()), stringBegin, length);

		// Ignore strings that contain non-printable chars
		if(mustBePrintable)
		{
			for(auto oneChar : str)
			{
				if(isPrintableChar(oneChar) == false)
				{
					str.clear();
					return 0;
				}
			}
		}
	}

	return length;
}

std::uint32_t PeLib::ImageLoader::dumpImage(const char * fileName)
{
	// Create the file for dumping
	std::ofstream fs(fileName, std::ofstream::binary);
	std::uint32_t bytesWritten = 0;

	if(fs.is_open())
	{
		// Allocate one page filled with zeros
		std::uint8_t zeroPage[PELIB_PAGE_SIZE] = {0};
		char * dataToWrite;

		// Write each page to the file
		for(auto & page : pages)
		{
			dataToWrite = (char *)(page.buffer.size() ? page.buffer.data() : zeroPage);
			fs.write(dataToWrite, PELIB_PAGE_SIZE);
			bytesWritten += PELIB_PAGE_SIZE;
		}
	}

	return bytesWritten;
}

std::uint32_t PeLib::ImageLoader::getImageBitability() const
{
	if(optionalHeader.Magic == PELIB_IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		return 64;

	// Default: 32-bit image
	return 32;
}

std::uint32_t PeLib::ImageLoader::vaToRva(std::uint64_t VirtualAddress) const
{
	if(getImageBase() <= VirtualAddress && VirtualAddress < getImageBase() + optionalHeader.SizeOfImage)
		return (std::uint32_t)(VirtualAddress - getImageBase());

	return UINT32_MAX;
}

std::uint32_t PeLib::ImageLoader::getFileOffsetFromRva(std::uint32_t rva) const
{
	// If we have sections loaded, then we calculate the file offset from section headers
	if(sections.size())
	{
		// Check whether the rva goes into any section
		for(auto & sectHdr : sections)
		{
			// Only if the pointer to raw data is not zero
			if(sectHdr.PointerToRawData != 0 && sectHdr.SizeOfRawData != 0)
			{
				std::uint32_t realPointerToRawData = sectHdr.PointerToRawData;
				std::uint32_t sectionRvaStart = sectHdr.VirtualAddress;
				std::uint32_t virtualSize = (sectHdr.VirtualSize != 0) ? sectHdr.VirtualSize : sectHdr.SizeOfRawData;

				// For multi-section images, real pointer to raw data is aligned down to sector size
				if(optionalHeader.SectionAlignment >= PELIB_PAGE_SIZE)
					realPointerToRawData = realPointerToRawData & ~(PELIB_SECTOR_SIZE - 1);

				// Is the RVA inside that section?
				if(sectionRvaStart <= rva && rva < (sectionRvaStart + virtualSize))
				{
					// Make sure we round the pointer to raw data down to PELIB_SECTOR_SIZE.
					// In case when PointerToRawData is less than 0x200, it maps to the header!
					return realPointerToRawData + (rva - sectionRvaStart);
				}
			}
		}

		// Check if the rva goes into the header
		return (rva < optionalHeader.SizeOfHeaders) ? rva : UINT32_MAX;
	}

	// The rva maps directly to the file offset
	return rva;
}

// similar to getFileOffsetFromRva, but the offset is within the real file and not memory image
std::uint32_t PeLib::ImageLoader::getValidOffsetFromRva(std::uint32_t rva) const
{
	// If we have sections loaded, then we calculate the file offset from section headers
	if (sections.size())
	{
		// Check whether the rva goes into any section
		for (auto& sectHdr : sections)
		{
			// Only if the pointer to raw data is not zero
			if (sectHdr.PointerToRawData != 0 && sectHdr.SizeOfRawData != 0)
			{
				std::uint32_t realPointerToRawData = sectHdr.PointerToRawData;
				std::uint32_t sectionRvaStart = sectHdr.VirtualAddress;
				std::uint32_t virtSize = sectHdr.VirtualSize;
				std::uint32_t rawSize = sectHdr.SizeOfRawData;

				// if rawSize is larger than what is mapped to memory, use only the mapped part
				std::uint32_t section_size = virtSize < rawSize ? virtSize : rawSize;
				// For multi-section images, real pointer to raw data is aligned down to sector size
				if (optionalHeader.SectionAlignment >= PELIB_PAGE_SIZE)
					realPointerToRawData = realPointerToRawData & ~(PELIB_SECTOR_SIZE - 1);

				// Check if the claimed real pointer can actually exist in the file
				std::uint64_t offset = rva - sectionRvaStart;
				bool fitsInFile = realPointerToRawData + offset < savedFileSize;

				// Is the RVA inside that part of the section, that is backed by disk data?
				if (sectionRvaStart <= rva && rva < (sectionRvaStart + section_size) && fitsInFile)
				{
					// Make sure we round the pointer to raw data down to PELIB_SECTOR_SIZE.
					// In case when PointerToRawData is less than 0x200, it maps to the header!
					return realPointerToRawData + offset;
				}
			}
		}

		// Check if the rva goes into the header
		return (rva < optionalHeader.SizeOfHeaders) ? rva : UINT32_MAX;
	}

	return UINT32_MAX;
}

std::uint32_t PeLib::ImageLoader::getFieldOffset(PELIB_MEMBER_TYPE field) const
{
	std::uint32_t imageBitability = getImageBitability();
	std::uint32_t fieldOffset;

	switch (field)
	{
		case PELIB_MEMBER_TYPE::OPTHDR_sizeof:
			return (imageBitability == 64) ? sizeof(PELIB_IMAGE_OPTIONAL_HEADER64) : sizeof(PELIB_IMAGE_OPTIONAL_HEADER32);

		case PELIB_MEMBER_TYPE::OPTHDR_sizeof_fixed:
			return (imageBitability == 64) ? offsetof(PELIB_IMAGE_OPTIONAL_HEADER64, DataDirectory)
				                           : offsetof(PELIB_IMAGE_OPTIONAL_HEADER32, DataDirectory);

		case PELIB_MEMBER_TYPE::OPTHDR_NumberOfRvaAndSizes:
			fieldOffset = (imageBitability == 64) ? offsetof(PELIB_IMAGE_OPTIONAL_HEADER64, NumberOfRvaAndSizes)
				                                  : offsetof(PELIB_IMAGE_OPTIONAL_HEADER32, NumberOfRvaAndSizes);
			return sizeof(PELIB_IMAGE_NT_SIGNATURE) + sizeof(PELIB_IMAGE_FILE_HEADER) + fieldOffset;

		case PELIB_MEMBER_TYPE::OPTHDR_DataDirectory:
			fieldOffset = (imageBitability == 64) ? offsetof(PELIB_IMAGE_OPTIONAL_HEADER64, DataDirectory)
				                                  : offsetof(PELIB_IMAGE_OPTIONAL_HEADER32, DataDirectory);
			return sizeof(PELIB_IMAGE_NT_SIGNATURE) + sizeof(PELIB_IMAGE_FILE_HEADER) + fieldOffset;

		case PELIB_MEMBER_TYPE::OPTHDR_DataDirectory_EXPORT_Rva:
			fieldOffset = (imageBitability == 64) ? offsetof(PELIB_IMAGE_OPTIONAL_HEADER64, DataDirectory)
				                                  : offsetof(PELIB_IMAGE_OPTIONAL_HEADER32, DataDirectory);
			return sizeof(PELIB_IMAGE_NT_SIGNATURE) +
				   sizeof(PELIB_IMAGE_FILE_HEADER) +
				   fieldOffset +
				   PELIB_IMAGE_DIRECTORY_ENTRY_EXPORT * sizeof(PELIB_IMAGE_DATA_DIRECTORY);

		case PELIB_MEMBER_TYPE::OPTHDR_DataDirectory_RSRC_Rva:
			fieldOffset = (imageBitability == 64) ? offsetof(PELIB_IMAGE_OPTIONAL_HEADER64, DataDirectory)
				                                  : offsetof(PELIB_IMAGE_OPTIONAL_HEADER32, DataDirectory);
			return sizeof(PELIB_IMAGE_NT_SIGNATURE) +
				   sizeof(PELIB_IMAGE_FILE_HEADER) +
				   fieldOffset +
				   PELIB_IMAGE_DIRECTORY_ENTRY_RESOURCE * sizeof(PELIB_IMAGE_DATA_DIRECTORY);

		case PELIB_MEMBER_TYPE::OPTHDR_DataDirectory_TLS_Rva:
			fieldOffset = (imageBitability == 64) ? offsetof(PELIB_IMAGE_OPTIONAL_HEADER64, DataDirectory)
				                                  : offsetof(PELIB_IMAGE_OPTIONAL_HEADER32, DataDirectory);
			return sizeof(PELIB_IMAGE_NT_SIGNATURE) +
				   sizeof(PELIB_IMAGE_FILE_HEADER) +
				   fieldOffset +
				   PELIB_IMAGE_DIRECTORY_ENTRY_TLS * sizeof(PELIB_IMAGE_DATA_DIRECTORY);

		case PELIB_MEMBER_TYPE::OPTHDR_DataDirectory_CONFIG_Rva:
			fieldOffset = (imageBitability == 64) ? offsetof(PELIB_IMAGE_OPTIONAL_HEADER64, DataDirectory)
				                                  : offsetof(PELIB_IMAGE_OPTIONAL_HEADER32, DataDirectory);
			return sizeof(PELIB_IMAGE_NT_SIGNATURE) +
				   sizeof(PELIB_IMAGE_FILE_HEADER) +
				   fieldOffset +
				   PELIB_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG * sizeof(PELIB_IMAGE_DATA_DIRECTORY);
	}

	return UINT32_MAX;
}

std::uint32_t PeLib::ImageLoader::getRealPointerToRawData(std::size_t sectionIndex) const
{
	if(sectionIndex >= sections.size())
		return UINT32_MAX;
	if(optionalHeader.SectionAlignment < PELIB_PAGE_SIZE)
		return sections[sectionIndex].PointerToRawData;

	return sections[sectionIndex].PointerToRawData & ~(PELIB_SECTOR_SIZE - 1);
}

std::uint32_t PeLib::ImageLoader::getRealSizeOfRawData(std::size_t sectionIndex) const
{
	if(sectionIndex >= sections.size())
		return UINT32_MAX;
	if(optionalHeader.SectionAlignment < PELIB_PAGE_SIZE)
		return sections[sectionIndex].SizeOfRawData;

	std::uint32_t beginOfRawData = sections[sectionIndex].PointerToRawData & ~(PELIB_SECTOR_SIZE - 1);
	std::uint32_t endOfRawData = sections[sectionIndex].PointerToRawData + AlignToSize(sections[sectionIndex].SizeOfRawData, optionalHeader.FileAlignment);
	return endOfRawData - beginOfRawData;
}

std::uint32_t PeLib::ImageLoader::getImageProtection(std::uint32_t sectionCharacteristics) const
{
	std::uint32_t Index = 0;

	if(sectionCharacteristics & PELIB_IMAGE_SCN_MEM_EXECUTE)
		Index |= 1;

	if(sectionCharacteristics & PELIB_IMAGE_SCN_MEM_READ)
		Index |= 2;

	if(sectionCharacteristics & PELIB_IMAGE_SCN_MEM_WRITE)
		Index |= 4;

	if(sectionCharacteristics & PELIB_IMAGE_SCN_MEM_SHARED)
		Index |= 8;

	return ImageProtectionArray[Index];
}

std::size_t PeLib::ImageLoader::getSectionIndexByRva(std::uint32_t Rva) const
{
	std::size_t sectionIndex = 0;

	for(const auto & section : sections)
	{
		if(section.VirtualAddress <= Rva && Rva < AlignToSize(section.VirtualAddress + section.VirtualSize, optionalHeader.SectionAlignment))
			return sectionIndex;
		sectionIndex++;
	}

	return SIZE_MAX;
}

//-----------------------------------------------------------------------------
// Manipulation with section data

void PeLib::ImageLoader::setPointerToSymbolTable(std::uint32_t pointerToSymbolTable)
{
	fileHeader.PointerToSymbolTable = pointerToSymbolTable;
}

void PeLib::ImageLoader::setCharacteristics(std::uint32_t characteristics)
{
	fileHeader.Characteristics = characteristics;
}

void PeLib::ImageLoader::setAddressOfEntryPoint(std::uint32_t addressOfEntryPoint)
{
	optionalHeader.AddressOfEntryPoint = addressOfEntryPoint;
}

void PeLib::ImageLoader::setSizeOfCode(
	std::uint32_t sizeOfCode,
	std::uint32_t baseOfCode)
{
	if(sizeOfCode != UINT32_MAX)
		optionalHeader.SizeOfCode = sizeOfCode;
	if(baseOfCode != UINT32_MAX)
		optionalHeader.BaseOfCode = baseOfCode;
}

void PeLib::ImageLoader::setDataDirectory(
	std::uint32_t entryIndex,
	std::uint32_t VirtualAddress,
	std::uint32_t Size)
{
	if(entryIndex < PELIB_IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
	{
		// Make sure there is enough entries
		if(entryIndex >= optionalHeader.NumberOfRvaAndSizes)
			optionalHeader.NumberOfRvaAndSizes = entryIndex + 1;

		if(VirtualAddress != UINT32_MAX)
			optionalHeader.DataDirectory[entryIndex].VirtualAddress = VirtualAddress;
		if(Size != UINT32_MAX)
			optionalHeader.DataDirectory[entryIndex].Size = Size;
	}
}

PeLib::PELIB_IMAGE_SECTION_HEADER * PeLib::ImageLoader::addSection(
	const char * name,
	std::uint32_t sectionSize)
{
	if(optionalHeader.FileAlignment == 0)
		return nullptr;
	if(optionalHeader.SectionAlignment == 0)
		return nullptr;
	if(sections.size() >= UINT16_MAX)
		return nullptr;

	// Calculate the new RVA and file offset
	std::uint32_t Rva = 0;
	std::uint32_t Raw = 0;
	calcNewSectionAddresses(Rva, Raw);

	// Create new section
	PELIB_SECTION_HEADER SectHdr;
	SectHdr.setName(name);
	SectHdr.setVirtualRange(Rva, AlignToSize(sectionSize, optionalHeader.SectionAlignment));
	SectHdr.setRawDataRange(Raw, AlignToSize(sectionSize, optionalHeader.FileAlignment));
	SectHdr.Characteristics = PELIB_IMAGE_SCN_MEM_WRITE | PELIB_IMAGE_SCN_MEM_READ | PELIB_IMAGE_SCN_CNT_INITIALIZED_DATA | PELIB_IMAGE_SCN_CNT_CODE;
	sections.push_back(SectHdr);

	// Return the header of the last section
	return getSectionHeader(sections.size() - 1);
}

void PeLib::ImageLoader::calcNewSectionAddresses(
	std::uint32_t & Rva,
	std::uint32_t & RawOffset)
{
	std::uint32_t NewRawOffset = optionalHeader.SizeOfHeaders;
	std::uint32_t NewRva = optionalHeader.SizeOfHeaders;

	for(const auto & section : sections)
	{
		if((section.VirtualAddress + section.VirtualSize) > NewRva)
			NewRva = section.VirtualAddress + section.VirtualSize;
		if((section.PointerToRawData + section.SizeOfRawData) > NewRawOffset)
			NewRawOffset = section.PointerToRawData + section.SizeOfRawData;
	}

	RawOffset = AlignToSize(NewRawOffset, optionalHeader.FileAlignment);
	Rva = AlignToSize(NewRva, optionalHeader.SectionAlignment);
}

void PeLib::ImageLoader::setSectionName(
	std::size_t sectionIndex,
	const char * newName)
{
	if(sectionIndex < sections.size())
	{
		sections[sectionIndex].setName(newName);
	}
}

void PeLib::ImageLoader::setSectionVirtualRange(
	std::size_t sectionIndex,
	std::uint32_t VirtualAddress,
	std::uint32_t VirtualSize)
{
	if(sectionIndex < sections.size())
	{
		sections[sectionIndex].setVirtualRange(VirtualAddress, VirtualSize);
	}
}

void PeLib::ImageLoader::setSectionRawDataRange(
	std::size_t sectionIndex,
	std::uint32_t PointerToRawData,
	std::uint32_t SizeOfRawData)
{
	if(sectionIndex < sections.size())
	{
		sections[sectionIndex].setRawDataRange(PointerToRawData, SizeOfRawData);
	}
}

void PeLib::ImageLoader::setSectionCharacteristics(
	std::size_t sectionIndex,
	std::uint32_t Characteristics)
{
	if(sectionIndex < sections.size())
	{
		sections[sectionIndex].Characteristics = Characteristics;
	}
}

int PeLib::ImageLoader::splitSection(
	std::size_t sectionIndex,
	const std::string & prevSectName,
	const std::string & nextSectName,
	std::uint32_t splitOffset)
{
	if(!optionalHeader.FileAlignment)
		return PeLib::ERROR_NO_FILE_ALIGNMENT;
	if(!optionalHeader.SectionAlignment)
		return PeLib::ERROR_NO_SECTION_ALIGNMENT;

	// Index needs to be in the range <0, NUMBER OF SECTIONS)
	if(sectionIndex > sections.size())
		return PeLib::ERROR_ENTRY_NOT_FOUND;

	// Offset at which the section is going to be split must be multiple of section alignment
	if(splitOffset & (getSectionAlignment() - 1))
		return PeLib::ERROR_NOT_ENOUGH_SPACE;

	// Do not allow to split if the offset of split is greater than the size of the section
	// Nor do allow the section with size 0 to be created
	if(splitOffset >= getSectionHeader(sectionIndex)->VirtualSize)
		return PeLib::ERROR_NOT_ENOUGH_SPACE;

	// Move every section located after the inserted section by one position
	sections.resize(sections.size() + 1);
	for(std::size_t i = sections.size() - 2; i >= sectionIndex + 1; --i)
		sections[i + 1] = sections[i];

	std::uint32_t originalSize = getSectionHeader(sectionIndex)->SizeOfRawData;

	// Setup the first of the new sections
	setSectionName(sectionIndex, prevSectName.c_str());
	setSectionRawDataRange(sectionIndex, UINT32_MAX, splitOffset);
	setSectionVirtualRange(sectionIndex, UINT32_MAX, splitOffset);

	// Setup the second of the new sections
	setSectionName(sectionIndex + 1, nextSectName.c_str());
	setSectionRawDataRange(sectionIndex + 1, sections[sectionIndex].PointerToRawData + splitOffset, originalSize - splitOffset);
	setSectionVirtualRange(sectionIndex + 1, sections[sectionIndex].VirtualAddress + splitOffset, originalSize - splitOffset);
	setSectionCharacteristics(sectionIndex + 1, PeLib::PELIB_IMAGE_SCN_MEM_WRITE | PeLib::PELIB_IMAGE_SCN_MEM_READ | PeLib::PELIB_IMAGE_SCN_CNT_INITIALIZED_DATA | PeLib::PELIB_IMAGE_SCN_CNT_CODE);
	return PeLib::ERROR_NONE;
}

void PeLib::ImageLoader::enlargeLastSection(std::uint32_t sizeIncrement)
{
	if(sections.size())
	{
		auto & lastSection = sections[sections.size() - 1];

		lastSection.VirtualSize = lastSection.SizeOfRawData = AlignToSize(lastSection.SizeOfRawData + sizeIncrement, getFileAlignment());
		optionalHeader.SizeOfImage = lastSection.VirtualAddress + lastSection.VirtualSize;
	}
}

int PeLib::ImageLoader::removeSection(std::size_t sectionIndex)
{
	if(sectionIndex >= getNumberOfSections())
		return ERROR_ENTRY_NOT_FOUND;

	const PELIB_SECTION_HEADER * pSectionHeader = getSectionHeader(sectionIndex);
	std::uint32_t virtualDiff = pSectionHeader->VirtualSize;
	std::uint32_t rawDiff = pSectionHeader->SizeOfRawData;

	for (std::size_t i = sectionIndex + 1; i < getNumberOfSections(); ++i)
	{
		pSectionHeader = getSectionHeader(i);

		setSectionVirtualRange(i, pSectionHeader->VirtualAddress - virtualDiff);
		setSectionRawDataRange(i, pSectionHeader->PointerToRawData - rawDiff);
	}

	sections.erase(sections.begin() + sectionIndex);
	return ERROR_NONE;
}

void PeLib::ImageLoader::makeValid()
{
	std::uint32_t imageBitability = getImageBitability();
	std::uint32_t sizeOfHeaders;
	std::uint32_t sizeOfImage;
	std::uint32_t dwOffsetDiff;
	std::uint32_t alignment;

	// Fix the NT signature
	ntSignature = PELIB_IMAGE_NT_SIGNATURE;    // 'PE'

	// Fix the IMAGE_FILE_HEADER
	fileHeader.Machine = (imageBitability == 64) ? PELIB_IMAGE_FILE_MACHINE_AMD64 : PELIB_IMAGE_FILE_MACHINE_I386;
	fileHeader.NumberOfSections = (std::uint16_t)sections.size();
	fileHeader.SizeOfOptionalHeader = getFieldOffset(PELIB_MEMBER_TYPE::OPTHDR_sizeof);
	fileHeader.Characteristics = (fileHeader.Characteristics != 0) ? fileHeader.Characteristics : PELIB_IMAGE_FILE_EXECUTABLE_IMAGE | PELIB_IMAGE_FILE_32BIT_MACHINE;

	// Fix the IMAGE_OPTIONAL_HEADER
	optionalHeader.Magic = (imageBitability == 64) ? PELIB_IMAGE_NT_OPTIONAL_HDR64_MAGIC : PELIB_IMAGE_NT_OPTIONAL_HDR32_MAGIC;
	optionalHeader.NumberOfRvaAndSizes = PELIB_IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

	alignment = AlignToSize(optionalHeader.SectionAlignment, PELIB_PAGE_SIZE);
	optionalHeader.SectionAlignment = (alignment != 0) ? alignment : PELIB_PAGE_SIZE;

	alignment = AlignToSize(optionalHeader.FileAlignment, PELIB_SECTOR_SIZE);
	optionalHeader.FileAlignment = (alignment != 0) ? alignment : PELIB_SECTOR_SIZE;

	sizeOfHeaders = dosHeader.e_lfanew + sizeof(PELIB_IMAGE_NT_SIGNATURE) + sizeof(PELIB_IMAGE_FILE_HEADER) + fileHeader.SizeOfOptionalHeader + fileHeader.NumberOfSections * sizeof(PELIB_IMAGE_SECTION_HEADER);
	optionalHeader.SizeOfHeaders = sizeOfHeaders = AlignToSize(sizeOfHeaders, optionalHeader.FileAlignment);

	sizeOfImage = AlignToSize(optionalHeader.SizeOfHeaders, optionalHeader.SectionAlignment);
	dwOffsetDiff = sizeOfHeaders - getSectionHeader(0)->PointerToRawData;
	for(std::uint16_t i = 0; i < fileHeader.NumberOfSections; i++)
	{
		const PELIB_SECTION_HEADER * pSectionHeader = getSectionHeader(i);

		sizeOfImage += AlignToSize(pSectionHeader->VirtualSize, optionalHeader.SectionAlignment);

		// If the size of headers changed, we need to move all section data further
		if(dwOffsetDiff)
			setSectionRawDataRange(i, pSectionHeader->PointerToRawData + dwOffsetDiff);
	}

	// Fixup the size of image
	optionalHeader.SizeOfImage = AlignToSize(sizeOfImage, optionalHeader.SectionAlignment);
}

//-----------------------------------------------------------------------------
// Loader error

int PeLib::ImageLoader::setLoaderError(PeLib::LoaderError ldrErr)
{
	// Do not override existing loader error
	if(ldrError == LDR_ERROR_NONE)
	{
		ldrError = ldrErr;
	}
	return ERROR_NONE;
}

PeLib::LoaderError PeLib::ImageLoader::loaderError() const
{
	return ldrError;
}

//-----------------------------------------------------------------------------
// Interface for loading files

int PeLib::ImageLoader::Load(
	ByteBuffer & fileData,
	std::uint32_t loadFlags)
{
	int fileError;

	// Remember the size of the file for later use
	savedFileSize = fileData.size();

	// Check and capture DOS header
	fileError = captureDosHeader(fileData);
	if(fileError != ERROR_NONE)
		return fileError;

	// Check and capture NT headers. Don't go any fuhrter than here if the NT headers were detected as bad.
	// Sample: retdec-regression-tests\tools\fileinfo\features\pe-loader-corruptions\001-pe-header-cut-001.ex_
	fileError = captureNtHeaders(fileData);
	if(fileError != ERROR_NONE || ldrError == LDR_ERROR_NTHEADER_OUT_OF_FILE)
		return fileError;

	// Check and capture section headers
	fileError = captureSectionHeaders(fileData);
	if(fileError != ERROR_NONE)
		return fileError;

	// Performed by Vista+
	if(forceIntegrityCheckEnabled && checkForBadCodeIntegrityImages(fileData))
		setLoaderError(LDR_ERROR_IMAGE_NON_EXECUTABLE);

	// Shall we map the image content?
	if(!(loadFlags & IoFlagHeadersOnly))
	{
		// Large amount of memory may be allocated during loading the image to memory.
		// We need to handle low memory condition carefully here
		try
		{
			// If there was no detected image error, map the image as if Windows loader would do
			if(isImageLoadable())
			{
				fileError = captureImageSections(fileData, loadFlags);

				// If needed, also perform image load config directory check
				if(fileError == ERROR_NONE)
				{
					if(checkImagePostMapping && checkForImageAfterMapping())
						setLoaderError(LDR_ERROR_IMAGE_NON_EXECUTABLE);
				}

				// Fix for images that modify themselves via relocations
				// Sample: 342EE6CCB04AB0194275360EE6F752007B9F0CE5420203A41C8C9B5BAC7626DD
				// Modifies code and import directory via relocation table.
				// This only works in Windows 7 or newer
				if(ldrError == LDR_ERROR_NONE && checkForInvalidImageRange())
				{
					// The image is gonna be relocated to address 0x10000,
					// which is the first valid base address that can happen
					// The relocation is done by ntdll!LdrpProtectAndRelocateImage -> ntdll!LdrRelocateImage
					relocateImage(0x10000);
				}
			}

			// If there was any kind of error that prevents the image from being mapped,
			// we load the content as-is and translate virtual addresses using getFileOffsetFromRva
			if(pages.size() == 0)
			{
				fileError = loadImageAsIs(fileData);
			}
		}
		catch(const std::bad_alloc&)
		{
			fileError = ERROR_NOT_ENOUGH_SPACE;
		}
	}

	return fileError;
}

int PeLib::ImageLoader::Load(
	std::istream & fs,
	std::streamoff fileOffset,
	std::uint32_t loadFlags)
{
	ByteBuffer fileData;
	std::streampos fileSize;
	std::size_t fileSize2;
	int fileError;

	// We need to reset the stream's error state for cases where the file size is too small
	// Sample: retdec-regression-tests\tools\fileinfo\bugs\exotic-pe-files\shutd0wn97.ex
	fs.clear();

	// Get the file size
	fs.seekg(0, std::ios::end);
	fileSize = fs.tellg();

	// Verify overflow of the file offset
	if(fileOffset > fileSize)
		return ERROR_INVALID_FILE;

	// Windows loader refuses to load any file which is larger than 0xFFFFFFFF
	if(((fileSize - fileOffset) >> 32) != 0)
		return setLoaderError(LDR_ERROR_FILE_TOO_BIG);
	fileSize2 = static_cast<std::size_t>(fileSize - fileOffset);

	// Optimization: Read and verify IMAGE_DOS_HEADER first to see if it *could* be a PE file
	// This prevents reading the entire file (possibly a very large one) just to find out it's not a PE
	if((fileError = verifyDosHeader(fs, fileOffset, fileSize2)) != ERROR_NONE)
		return fileError;

	// Resize the vector so it can hold entire file. Note that this can
	// potentially allocate a very large memory block, so we need to handle that carefully
	try
	{
		fileData.resize(fileSize2);
	}
	catch(const std::bad_alloc&)
	{
		return ERROR_NOT_ENOUGH_SPACE;
	}

	// Read the entire file to memory. Note that under Windows
	// and under low memory condition, the underlying OS call (NtReadFile)
	// can fail on low memory. When that happens, fs.read will read less than
	// required. We need to verify the number of bytes read and return the apropriate error code.
	fs.seekg(fileOffset);
	fs.read(reinterpret_cast<char*>(fileData.data()), fileSize2);
	if(fs.gcount() < (fileSize - fileOffset))
	{
		return ERROR_NOT_ENOUGH_SPACE;
	}

	// Call the Load interface on char buffer
	return Load(fileData, loadFlags);
}

int PeLib::ImageLoader::Load(
	const char * fileName,
	std::uint32_t loadFlags)
{
	std::ifstream fs(fileName, std::ifstream::in | std::ifstream::binary);
	if(!fs.is_open())
		return ERROR_OPENING_FILE;

	return Load(fs, 0, loadFlags);
}

//-----------------------------------------------------------------------------
// Interface for saving to file

int PeLib::ImageLoader::Save(
	std::ostream & fs,
	std::streamoff fileOffset,
	std::uint32_t saveFlags)
{
	int fileError;

	// This save mode is intended for unpackers. Headers are constructed
	// from metadata and sections are filled with zeros
	if(saveFlags & IoFlagNewFile)
	{
		// Save the DOS header
		fileError = saveDosHeaderNew(fs, fileOffset);
		if(fileError != ERROR_NONE)
			return fileError;

		// Save the NT headers
		fileError = saveNtHeadersNew(fs, fileOffset + dosHeader.e_lfanew);
		if(fileError != ERROR_NONE)
			return fileError;

		// Check and capture section headers
		fileOffset = fileOffset + dosHeader.e_lfanew + sizeof(PELIB_IMAGE_NT_SIGNATURE) + sizeof(PELIB_IMAGE_FILE_HEADER) + fileHeader.SizeOfOptionalHeader;
		fileError = saveSectionHeadersNew(fs, fileOffset);
		if(fileError != ERROR_NONE)
			return fileError;

		// Write section data to the file, up to size of image
		if(!(saveFlags & IoFlagHeadersOnly))
		{
			// Get the curent file offset and file size
			fileOffset += sections.size() * sizeof(PELIB_IMAGE_SECTION_HEADER);
			std::streamoff fileSize = fileOffset;

			// Estimate the file size with data
			for(const auto & section : sections)
			{
				if(section.SizeOfRawData != 0)
				{
					if((section.PointerToRawData + section.SizeOfRawData) > fileSize)
						fileSize = section.PointerToRawData + section.SizeOfRawData;
				}
			}

			// Shall we write data to the file?
			if(fileSize > fileOffset)
			{
				std::vector<char> ZeroBuffer(fileSize - fileOffset);

				fs.seekp(fileOffset, std::ios::beg);
				fs.write(ZeroBuffer.data(), ZeroBuffer.size());
			}
		}
	}
	else
	{
		// Save the DOS header
		fileError = saveDosHeader(fs, fileOffset);
		if(fileError != ERROR_NONE)
			return fileError;

		// Save the NT headers
		fileError = saveNtHeaders(fs, fileOffset + dosHeader.e_lfanew);
		if(fileError != ERROR_NONE)
			return fileError;

		// Check and capture section headers
		fileOffset = fileOffset + dosHeader.e_lfanew + sizeof(PELIB_IMAGE_NT_SIGNATURE) + sizeof(PELIB_IMAGE_FILE_HEADER) + fileHeader.SizeOfOptionalHeader;
		fileError = saveSectionHeaders(fs, fileOffset);
		if(fileError != ERROR_NONE)
			return fileError;

		// Write section data to the file, up to size of image
		if(!(saveFlags & IoFlagHeadersOnly))
		{
			// Write each section
			for(const auto & section : sections)
			{
				fileError = saveToFile(fs, section.PointerToRawData, section.VirtualAddress, section.SizeOfRawData);
				if(fileError != ERROR_NONE)
					return fileError;
			}
		}
	}

	return ERROR_NONE;
}

int PeLib::ImageLoader::Save(
	const char * fileName,
	std::uint32_t saveFlags)
{
    std::ofstream fs(fileName, std::ifstream::out | std::ifstream::binary);
    if(!fs.is_open())
        return ERROR_OPENING_FILE;

    return Save(fs, 0, saveFlags);
}

//-----------------------------------------------------------------------------
// Protected functions

void PeLib::ImageLoader::readFromPage(
	PELIB_FILE_PAGE & page,
	void * buffer,
	std::size_t offsetInPage,
	std::size_t bytesInPage)
{
	// Is it a page with actual data?
	if(page.buffer.size())
	{
		memcpy(buffer, page.buffer.data() + offsetInPage, bytesInPage);
	}
	else
	{
		memset(buffer, 0, bytesInPage);
	}
}

void PeLib::ImageLoader::writeToPage(
	PELIB_FILE_PAGE & page,
	void * buffer,
	std::size_t offsetInPage,
	std::size_t bytesInPage)
{
	// Write the data to the page
	page.writeToPage(buffer, offsetInPage, bytesInPage);
}

std::uint32_t PeLib::ImageLoader::readWriteImage(
	void * buffer,
	std::uint32_t rva,
	std::uint32_t bytesToRead,
	READWRITE ReadWrite)
{
	std::uint32_t bytesRead = 0;
	std::uint32_t rvaEnd = rva + bytesToRead;

	// Check the last possible address where we read
	if(rvaEnd > getSizeOfImageAligned())
		rvaEnd = getSizeOfImageAligned();

	// Is the offset within the image?
	if(rva < rvaEnd)
	{
		std::uint8_t * bufferPtr = static_cast<std::uint8_t *>(buffer);

		while(rva < rvaEnd)
		{
			std::uint32_t offsetInPage = rva & (PELIB_PAGE_SIZE - 1);
			std::uint32_t bytesInPage = PELIB_PAGE_SIZE - offsetInPage;
			std::size_t pageIndex = rva / PELIB_PAGE_SIZE;

			// Perhaps the last page loaded?
			if(bytesInPage > (rvaEnd - rva))
				bytesInPage = (rvaEnd - rva);

			// The page index must be in range
			if(pageIndex < pages.size())
			{
				ReadWrite(pages[pageIndex], bufferPtr, offsetInPage, bytesInPage);
			}
			else
			{
				memset(bufferPtr, 0, bytesInPage);
			}

			// Move pointers
			bufferPtr += bytesInPage;
			bytesRead += bytesInPage;
			rva += bytesInPage;
		}
	}

	// Return the number of bytes that were read
	return bytesRead;
}

std::uint32_t PeLib::ImageLoader::readWriteImageFile(
	void * buffer,
	std::uint32_t rva,
	std::uint32_t bytesToRead,
	bool bReadOperation)
{
	std::uint32_t fileOffset = getFileOffsetFromRva(rva);

	// Make sure we won't read/write past the end of the data
	if(fileOffset > rawFileData.size())
		return 0;
	if((fileOffset + bytesToRead) > rawFileData.size())
		bytesToRead = (std::uint32_t)(rawFileData.size() - fileOffset);

	// Read the data
	if(bytesToRead != 0)
	{
		if(bReadOperation)
			memcpy(buffer, rawFileData.data() + fileOffset, bytesToRead);
		else
			memcpy(rawFileData.data() + fileOffset, buffer, bytesToRead);
	}

	// Return the number of bytes read/written
	return bytesToRead;
}

//
// There is a specific piece of code in MiParseImageSectionHeaders (see below).
// Note that this is done on the raw image data *BEFORE* the image is mapped to sections
// Causes map difference on this sample: 2e26926a701df980fb56e5905a93bf2d7ba6981ccabc81cf251b3c0ed6afdc26
// * SizeOfHeaders:                0x1000
// * PointerToRawData section[1]:  0x0200 - this actually points to the IMAGE_SECTION_HEADER of section[3]
// Because the PointerToRawData of section[3] is set to zero, the RVA 0xA014 is also set to zero
//
// The code is here:
//
//   //
//   // Fix for Borland linker problem.  The SizeOfRawData can
//   // be a zero, but the PointerToRawData is not zero.
//   // Set it to zero.
//   //
//
//  if(SectionTableEntry->SizeOfRawData == 0) {
//      SectionTableEntry->PointerToRawData = 0;
//  }
//

void PeLib::ImageLoader::processSectionHeader(
	PELIB_IMAGE_SECTION_HEADER * pSectionHeader)
{
	// Note: Retdec's regression tests don't like it, because they require section headers to have original data
	// Also signature verification stops working if we modify the original data
	if(windowsBuildNumber != 0)
	{
		// Fix the section header. Note that this will modify the data in the on-disk version
		// of the image. Any section that will become mapped to this section header
		// will have the corresponding DWORD zeroed, as expected.
		if(pSectionHeader->PointerToRawData != 0 && pSectionHeader->SizeOfRawData == 0)
		{
			pSectionHeader->PointerToRawData = 0;
		}
	}
}

//-----------------------------------------------------------------------------
// Processes relocation entry for IA64 relocation bundle

#define EMARCH_ENC_I17_IMM7B_INST_WORD_X         3
#define EMARCH_ENC_I17_IMM7B_SIZE_X              7
#define EMARCH_ENC_I17_IMM7B_INST_WORD_POS_X     4
#define EMARCH_ENC_I17_IMM7B_VAL_POS_X           0

#define EMARCH_ENC_I17_IMM9D_INST_WORD_X         3
#define EMARCH_ENC_I17_IMM9D_SIZE_X              9
#define EMARCH_ENC_I17_IMM9D_INST_WORD_POS_X     18
#define EMARCH_ENC_I17_IMM9D_VAL_POS_X           7

#define EMARCH_ENC_I17_IMM5C_INST_WORD_X         3
#define EMARCH_ENC_I17_IMM5C_SIZE_X              5
#define EMARCH_ENC_I17_IMM5C_INST_WORD_POS_X     13
#define EMARCH_ENC_I17_IMM5C_VAL_POS_X           16

#define EMARCH_ENC_I17_IC_INST_WORD_X            3
#define EMARCH_ENC_I17_IC_SIZE_X                 1
#define EMARCH_ENC_I17_IC_INST_WORD_POS_X        12
#define EMARCH_ENC_I17_IC_VAL_POS_X              21

#define EMARCH_ENC_I17_IMM41a_INST_WORD_X        1
#define EMARCH_ENC_I17_IMM41a_SIZE_X             10
#define EMARCH_ENC_I17_IMM41a_INST_WORD_POS_X    14
#define EMARCH_ENC_I17_IMM41a_VAL_POS_X          22

#define EMARCH_ENC_I17_IMM41b_INST_WORD_X        1
#define EMARCH_ENC_I17_IMM41b_SIZE_X             8
#define EMARCH_ENC_I17_IMM41b_INST_WORD_POS_X    24
#define EMARCH_ENC_I17_IMM41b_VAL_POS_X          32

#define EMARCH_ENC_I17_IMM41c_INST_WORD_X        2
#define EMARCH_ENC_I17_IMM41c_SIZE_X             23
#define EMARCH_ENC_I17_IMM41c_INST_WORD_POS_X    0
#define EMARCH_ENC_I17_IMM41c_VAL_POS_X          40

#define EMARCH_ENC_I17_SIGN_INST_WORD_X          3
#define EMARCH_ENC_I17_SIGN_SIZE_X               1
#define EMARCH_ENC_I17_SIGN_INST_WORD_POS_X      27
#define EMARCH_ENC_I17_SIGN_VAL_POS_X            63

#define EXT_IMM64(Value, SourceValue32, Size, InstPos, ValPos)   \
    Value |= (((std::uint64_t)((SourceValue32 >> InstPos) & (((std::uint64_t)1 << Size) - 1))) << ValPos)

#define INS_IMM64(Value, TargetValue32, Size, InstPos, ValPos)   \
    TargetValue32 = (TargetValue32 & ~(((1 << Size) - 1) << InstPos)) |  \
          ((std::uint32_t)((((std::uint64_t)Value >> ValPos) & (((std::uint64_t)1 << Size) - 1))) << InstPos)

bool PeLib::ImageLoader::processImageRelocation_IA64_IMM64(
	std::uint32_t fixupAddress,
	std::uint64_t difference)
{
	std::uint64_t Value64 = 0;
	std::uint32_t BundleBlock[4];

	// Align the fixup address to bundle address
	fixupAddress = fixupAddress & ~0x0F;

	// Load the 4 32-bit values from the target
	if(readImage(BundleBlock, fixupAddress, sizeof(BundleBlock)) != sizeof(BundleBlock))
		return false;

	//
	// Extract the IMM64 from bundle
	//

	EXT_IMM64(Value64, BundleBlock[EMARCH_ENC_I17_IMM7B_INST_WORD_X],
			  EMARCH_ENC_I17_IMM7B_SIZE_X,
			  EMARCH_ENC_I17_IMM7B_INST_WORD_POS_X,
			  EMARCH_ENC_I17_IMM7B_VAL_POS_X);
	EXT_IMM64(Value64, BundleBlock[EMARCH_ENC_I17_IMM9D_INST_WORD_X],
			  EMARCH_ENC_I17_IMM9D_SIZE_X,
			  EMARCH_ENC_I17_IMM9D_INST_WORD_POS_X,
			  EMARCH_ENC_I17_IMM9D_VAL_POS_X);
	EXT_IMM64(Value64, BundleBlock[EMARCH_ENC_I17_IMM5C_INST_WORD_X],
			  EMARCH_ENC_I17_IMM5C_SIZE_X,
			  EMARCH_ENC_I17_IMM5C_INST_WORD_POS_X,
			  EMARCH_ENC_I17_IMM5C_VAL_POS_X);
	EXT_IMM64(Value64, BundleBlock[EMARCH_ENC_I17_IC_INST_WORD_X],
			  EMARCH_ENC_I17_IC_SIZE_X,
			  EMARCH_ENC_I17_IC_INST_WORD_POS_X,
			  EMARCH_ENC_I17_IC_VAL_POS_X);
	EXT_IMM64(Value64, BundleBlock[EMARCH_ENC_I17_IMM41a_INST_WORD_X],
			  EMARCH_ENC_I17_IMM41a_SIZE_X,
			  EMARCH_ENC_I17_IMM41a_INST_WORD_POS_X,
			  EMARCH_ENC_I17_IMM41a_VAL_POS_X);
	EXT_IMM64(Value64, BundleBlock[EMARCH_ENC_I17_IMM41b_INST_WORD_X],
			  EMARCH_ENC_I17_IMM41b_SIZE_X,
			  EMARCH_ENC_I17_IMM41b_INST_WORD_POS_X,
			  EMARCH_ENC_I17_IMM41b_VAL_POS_X);
	EXT_IMM64(Value64, BundleBlock[EMARCH_ENC_I17_IMM41c_INST_WORD_X],
			  EMARCH_ENC_I17_IMM41c_SIZE_X,
			  EMARCH_ENC_I17_IMM41c_INST_WORD_POS_X,
			  EMARCH_ENC_I17_IMM41c_VAL_POS_X);
	EXT_IMM64(Value64, BundleBlock[EMARCH_ENC_I17_SIGN_INST_WORD_X],
			  EMARCH_ENC_I17_SIGN_SIZE_X,
			  EMARCH_ENC_I17_SIGN_INST_WORD_POS_X,
			  EMARCH_ENC_I17_SIGN_VAL_POS_X);
	//
	// Update 64-bit address
	//

	Value64 += difference;

	//
	// Insert IMM64 into bundle
	//

	INS_IMM64(Value64, BundleBlock[EMARCH_ENC_I17_IMM7B_INST_WORD_X],
			  EMARCH_ENC_I17_IMM7B_SIZE_X,
			  EMARCH_ENC_I17_IMM7B_INST_WORD_POS_X,
			  EMARCH_ENC_I17_IMM7B_VAL_POS_X);
	INS_IMM64(Value64, BundleBlock[EMARCH_ENC_I17_IMM9D_INST_WORD_X],
			  EMARCH_ENC_I17_IMM9D_SIZE_X,
			  EMARCH_ENC_I17_IMM9D_INST_WORD_POS_X,
			  EMARCH_ENC_I17_IMM9D_VAL_POS_X);
	INS_IMM64(Value64, BundleBlock[EMARCH_ENC_I17_IMM5C_INST_WORD_X],
			  EMARCH_ENC_I17_IMM5C_SIZE_X,
			  EMARCH_ENC_I17_IMM5C_INST_WORD_POS_X,
			  EMARCH_ENC_I17_IMM5C_VAL_POS_X);
	INS_IMM64(Value64, BundleBlock[EMARCH_ENC_I17_IC_INST_WORD_X],
			  EMARCH_ENC_I17_IC_SIZE_X,
			  EMARCH_ENC_I17_IC_INST_WORD_POS_X,
			  EMARCH_ENC_I17_IC_VAL_POS_X);
	INS_IMM64(Value64, BundleBlock[EMARCH_ENC_I17_IMM41a_INST_WORD_X],
			  EMARCH_ENC_I17_IMM41a_SIZE_X,
			  EMARCH_ENC_I17_IMM41a_INST_WORD_POS_X,
			  EMARCH_ENC_I17_IMM41a_VAL_POS_X);
	INS_IMM64(Value64, BundleBlock[EMARCH_ENC_I17_IMM41b_INST_WORD_X],
			  EMARCH_ENC_I17_IMM41b_SIZE_X,
			  EMARCH_ENC_I17_IMM41b_INST_WORD_POS_X,
			  EMARCH_ENC_I17_IMM41b_VAL_POS_X);
	INS_IMM64(Value64, BundleBlock[EMARCH_ENC_I17_IMM41c_INST_WORD_X],
			  EMARCH_ENC_I17_IMM41c_SIZE_X,
			  EMARCH_ENC_I17_IMM41c_INST_WORD_POS_X,
			  EMARCH_ENC_I17_IMM41c_VAL_POS_X);
	INS_IMM64(Value64, BundleBlock[EMARCH_ENC_I17_SIGN_INST_WORD_X],
			  EMARCH_ENC_I17_SIGN_SIZE_X,
			  EMARCH_ENC_I17_SIGN_INST_WORD_POS_X,
			  EMARCH_ENC_I17_SIGN_VAL_POS_X);

	// Write the bundle block back to the image
	return (writeImage(BundleBlock, fixupAddress, sizeof(BundleBlock)) == sizeof(BundleBlock));
}

bool PeLib::ImageLoader::processImageRelocations(
	std::uint64_t oldImageBase,
	std::uint64_t newImageBase,
	std::uint32_t VirtualAddress,
	std::uint32_t Size)
{
	std::uint64_t difference = (newImageBase - oldImageBase);
	std::uint8_t * bufferEnd;
	std::uint8_t * bufferPtr;
	std::uint8_t * buffer;

	// No not accept anything less than size of relocation block
	// Also refuse to process suspiciously large relocation blocks
	if(Size < sizeof(PELIB_IMAGE_BASE_RELOCATION) || Size > PELIB_SIZE_10MB)
		return false;

	// Allocate and read the relocation block
	bufferPtr = buffer = new std::uint8_t[Size];
	if(buffer != nullptr)
	{
		// Read the relocations from the file
		bufferEnd = buffer + readImage(buffer, VirtualAddress, Size);

		// Keep going while there is relocation blocks
		while((bufferPtr + sizeof(PELIB_IMAGE_BASE_RELOCATION)) <= bufferEnd)
		{
			PELIB_IMAGE_BASE_RELOCATION * pRelocBlock = (PELIB_IMAGE_BASE_RELOCATION *)(bufferPtr);
			std::uint16_t * typeAndOffset = (std::uint16_t * )(pRelocBlock + 1);
			std::uint32_t numRelocations;

			// Skip relocation blocks that have invalid values
			if(!isValidImageBlock(pRelocBlock->VirtualAddress, pRelocBlock->SizeOfBlock))
				break;

			// Skip relocation blocks which have invalid size in the header
			if(pRelocBlock->SizeOfBlock <= sizeof(PELIB_IMAGE_BASE_RELOCATION))
			{
				bufferPtr += sizeof(PELIB_IMAGE_BASE_RELOCATION);
				continue;
			}

			// Windows loader seems to skip relocation blocks that go into the 0-th page (the header)
			// Sample: e380e6968f1b431e245f811f94cef6a5b6e17fd7c90ef283338fa1959eb3c536
			if(isZeroPage(pRelocBlock->VirtualAddress))
			{
				bufferPtr += pRelocBlock->SizeOfBlock;
				continue;
			}

			// Calculate number of relocation entries. Prevent buffer overflow
			if((bufferPtr + pRelocBlock->SizeOfBlock) > bufferEnd)
				pRelocBlock->SizeOfBlock = bufferEnd - bufferPtr;
			numRelocations = (pRelocBlock->SizeOfBlock - sizeof(PELIB_IMAGE_BASE_RELOCATION)) / sizeof(std::uint16_t);

			// Parse relocations
			for(std::uint32_t i = 0; i < numRelocations; i++)
			{
				std::uint32_t fixupAddress = pRelocBlock->VirtualAddress + (typeAndOffset[i] & 0x0FFF);
				std::int32_t temp;

				switch(typeAndOffset[i] >> 12)
				{
					// The base relocation applies the difference to the 64-bit field at offset.
					case PELIB_IMAGE_REL_BASED_DIR64:
					{
						std::int64_t fixupValue = 0;

						if(readImage(&fixupValue, fixupAddress, sizeof(fixupValue)) != sizeof(fixupValue))
							break;
						fixupValue += difference;
						writeImage(&fixupValue, fixupAddress, sizeof(fixupValue));
						break;
					}

					// The base relocation applies all 32 bits of the difference to the 32-bit field at offset.
					case PELIB_IMAGE_REL_BASED_HIGHLOW:
					{
						std::int32_t fixupValue = 0;

						if(readImage(&fixupValue, fixupAddress, sizeof(fixupValue)) != sizeof(fixupValue))
							break;
						fixupValue += (std::int32_t)difference;
						writeImage(&fixupValue, fixupAddress, sizeof(fixupValue));
						break;
					}

					// The base relocation adds the high 16 bits of the difference to the 16-bit field at offset.
					case PELIB_IMAGE_REL_BASED_HIGH:
					{
						std::int16_t fixupValue = 0;

						if(readImage(&fixupValue, fixupAddress, sizeof(fixupValue)) != sizeof(fixupValue))
							break;
						temp = (fixupValue << 16);
						temp += (std::int32_t)difference;
						fixupValue = (std::int16_t)(temp >> 16);
						writeImage(&fixupValue, fixupAddress, sizeof(fixupValue));
						break;
					}

					// The base relocation adds the high 16 bits of the difference to the 16-bit field at offset.
					case PELIB_IMAGE_REL_BASED_HIGHADJ:
					{
						std::int16_t fixupValue = 0;

						if(readImage(&fixupValue, fixupAddress, sizeof(fixupValue)) != sizeof(fixupValue))
							break;
						temp = (fixupValue << 16);
						temp += (std::int32_t)typeAndOffset[++i];
						temp += (std::int32_t)difference;
						temp += 0x8000;
						fixupValue = (std::int16_t)(temp >> 16);
						writeImage(&fixupValue, fixupAddress, sizeof(fixupValue));
						break;
					}

					// The base relocation adds the low 16 bits of the difference to the 16-bit field at offset.
					case PELIB_IMAGE_REL_BASED_LOW:
					{
						std::int16_t fixupValue = 0;

						if(readImage(&fixupValue, fixupAddress, sizeof(fixupValue)) != sizeof(fixupValue))
							break;
						fixupValue = (std::int16_t)((std::int32_t)fixupValue + difference);
						writeImage(&fixupValue, fixupAddress, sizeof(fixupValue));
						break;
					}

					// Relocate a MIPS jump address.
					case PELIB_IMAGE_REL_BASED_MIPS_JMPADDR:
					{
						std::uint32_t fixupValue = 0;

						if(readImage(&fixupValue, fixupAddress, sizeof(fixupValue)) != sizeof(fixupValue))
							break;
						temp = (fixupValue & 0x3ffffff) << 2;
						temp += (std::int32_t)difference;
						fixupValue = (fixupValue & ~0x3ffffff) | ((temp >> 2) & 0x3ffffff);
						writeImage(&fixupValue, fixupAddress, sizeof(fixupValue));
						break;
					}

					case PELIB_IMAGE_REL_BASED_IA64_IMM64:
						processImageRelocation_IA64_IMM64(fixupAddress, difference);
						break;

					// Absolute - no fixup required.
					case PELIB_IMAGE_REL_BASED_ABSOLUTE:
						break;

					default:
						return false;
				}
			}

			// Move to the next relocation block
			bufferPtr = bufferPtr + pRelocBlock->SizeOfBlock;
		}

		// Free the relocation buffer
		delete [] buffer;
	}

	return true;
}

void PeLib::ImageLoader::writeNewImageBase(std::uint64_t newImageBase)
{
	std::uint32_t offset = dosHeader.e_lfanew + sizeof(std::uint32_t) + sizeof(PELIB_IMAGE_FILE_HEADER);

	// 64-bit images
	if(optionalHeader.Magic == PELIB_IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		PELIB_IMAGE_OPTIONAL_HEADER64 header64{};
		std::uint32_t sizeOfOptionalHeader = offsetof(PELIB_IMAGE_OPTIONAL_HEADER64, DataDirectory);

		readImage(&header64, offset, sizeOfOptionalHeader);
		header64.ImageBase = newImageBase;
		writeImage(&header64, offset, sizeOfOptionalHeader);
	}

	// 32-bit images
	if(optionalHeader.Magic == PELIB_IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		PELIB_IMAGE_OPTIONAL_HEADER32 header32{};
		std::uint32_t sizeOfOptionalHeader = offsetof(PELIB_IMAGE_OPTIONAL_HEADER32, DataDirectory);

		readImage(&header32, offset, sizeOfOptionalHeader);
		header32.ImageBase = (std::uint32_t)newImageBase;
		writeImage(&header32, offset, sizeOfOptionalHeader);
	}
}

int PeLib::ImageLoader::captureDosHeader(ByteBuffer & fileData)
{
	std::uint8_t * fileBegin = fileData.data();
	std::uint8_t * fileEnd = fileBegin + fileData.size();

	// Capture the DOS header
	if((fileBegin + sizeof(PELIB_IMAGE_DOS_HEADER)) >= fileEnd)
		return ERROR_INVALID_FILE;
	memcpy(&dosHeader, fileBegin, sizeof(PELIB_IMAGE_DOS_HEADER));

	// Verify DOS header
	return verifyDosHeader(dosHeader, fileData.size());
}

int PeLib::ImageLoader::saveToFile(
	std::ostream & fs,
	std::streamoff fileOffset,
	std::size_t rva,
	std::size_t length)
{
	std::vector<char> DataBuffer(length);

	readImage(DataBuffer.data(), rva, length);
	fs.seekp(fileOffset, std::ios::beg);
	fs.write(DataBuffer.data(), length);
	return ERROR_NONE;
}

int PeLib::ImageLoader::saveDosHeaderNew(
	std::ostream & fs,
	std::streamoff fileOffset)
{
	// Write DOS header as-is
	fs.seekp(fileOffset, std::ios::beg);
	fs.write(reinterpret_cast<char *>(&dosHeader), sizeof(PELIB_IMAGE_DOS_HEADER));
	return ERROR_NONE;
}

int PeLib::ImageLoader::saveDosHeader(
	std::ostream & fs,
	std::streamoff fileOffset)
{
	// Request some reasonable maximum to the DOS header size
	if(dosHeader.e_lfanew > PELIB_PAGE_SIZE * 10)
		return ERROR_INVALID_FILE;
	return saveToFile(fs, fileOffset, 0, dosHeader.e_lfanew);
}

int PeLib::ImageLoader::captureNtHeaders(ByteBuffer & fileData)
{
	std::uint8_t * fileBegin = fileData.data();
	std::uint8_t * filePtr = fileBegin + dosHeader.e_lfanew;
	std::uint8_t * fileEnd = fileBegin + fileData.size();
	std::size_t ntHeaderSize;
	std::uint16_t optionalHeaderMagic = PELIB_IMAGE_NT_OPTIONAL_HDR32_MAGIC;

	// Windows 7 or newer require that the file size is greater or equal to sizeof(IMAGE_NT_HEADERS)
	// Note that 64-bit kernel requires this to be sizeof(IMAGE_NT_HEADERS64)
	if(ntHeadersSizeCheck)
	{
		std::uint32_t minFileSize = dosHeader.e_lfanew + sizeof(std::uint32_t) + sizeof(PELIB_IMAGE_FILE_HEADER) + sizeof(PELIB_IMAGE_OPTIONAL_HEADER32);

		if((fileBegin + minFileSize) > fileEnd)
			return setLoaderError(LDR_ERROR_NTHEADER_OUT_OF_FILE);
	}

	// Capture the NT signature
	if((filePtr + sizeof(std::uint32_t)) >= fileEnd)
	{
		setLoaderError(LDR_ERROR_NTHEADER_OUT_OF_FILE);
		return ERROR_INVALID_FILE;
	}

	// Check the NT signature
	if((ntSignature = *(std::uint32_t *)(filePtr)) != PELIB_IMAGE_NT_SIGNATURE)
	{
		setLoaderError(LDR_ERROR_NO_NT_SIGNATURE);
		return ERROR_INVALID_FILE;
	}
	filePtr += sizeof(std::uint32_t);

	// Capture the file header. Note that if the NT header is cut, we still want to recognize the file as PE
	if((filePtr + sizeof(PELIB_IMAGE_FILE_HEADER)) >= fileEnd)
	{
		setLoaderError(LDR_ERROR_NTHEADER_OUT_OF_FILE);
		return ERROR_NONE;
	}
	memcpy(&fileHeader, filePtr, sizeof(PELIB_IMAGE_FILE_HEADER));

	// 7baebc6d9f2185fafa760c875ab1386f385a0b3fecf2e6ae339abb4d9ac58f3e
	if(fileHeader.Machine == 0 && fileHeader.SizeOfOptionalHeader == 0)
		setLoaderError(LDR_ERROR_FILE_HEADER_INVALID);
	if(!(fileHeader.Characteristics & PELIB_IMAGE_FILE_EXECUTABLE_IMAGE))
		setLoaderError(LDR_ERROR_IMAGE_NON_EXECUTABLE);
	filePtr += sizeof(PELIB_IMAGE_FILE_HEADER);

	// Windows XP: Number of section must be 96
	// Windows 7: Number of section must be 192
	if(fileHeader.NumberOfSections > maxSectionCount)
		setLoaderError(LDR_ERROR_IMAGE_NON_EXECUTABLE);

	// Check the position of the NT header for integer overflow and for file size overflow
	ntHeaderSize = sizeof(std::uint32_t) + sizeof(PELIB_IMAGE_FILE_HEADER) + fileHeader.SizeOfOptionalHeader;
	if((dosHeader.e_lfanew + ntHeaderSize) < dosHeader.e_lfanew)
		setLoaderError(LDR_ERROR_NTHEADER_OFFSET_OVERFLOW);

	// Capture optional header. Note that we need to parse it
	// according to IMAGE_OPTIONAL_HEADER::Magic
	if((filePtr + sizeof(std::uint16_t)) < fileEnd)
		optionalHeaderMagic = *(std::uint16_t *)(filePtr);
	if(optionalHeaderMagic == PELIB_IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		captureOptionalHeader64(fileBegin, filePtr, fileEnd);
	else
		captureOptionalHeader32(fileBegin, filePtr, fileEnd);

	// Performed by Windows 8+ (nt!MiRelocateImage). If check fails,
	// NtCreateSection returns STATUS_INVALID_IMAGE_FORMAT (0xC000007B)
	// In Windows 10 (since build 10240), this check is only performed for "legacy" images (I386 or AMD64)
	// Sample: 04d3577d1b6309a0032d4c4c1252c55416a09bb617aebafe512fffbdd4f08f18
	if(architectureSpecificChecks && checkForBadArchitectureSpecific())
		setLoaderError(LDR_ERROR_IMAGE_NON_EXECUTABLE);

	// SizeOfHeaders must be nonzero if not a single subsection
	if(optionalHeader.SectionAlignment >= PELIB_PAGE_SIZE && optionalHeader.SizeOfHeaders == 0)
		setLoaderError(LDR_ERROR_SIZE_OF_HEADERS_ZERO);

	// File alignment must not be 0
	if(optionalHeader.FileAlignment == 0)
		setLoaderError(LDR_ERROR_FILE_ALIGNMENT_ZERO);

	// File alignment must be a power of 2
	if(optionalHeader.FileAlignment & (optionalHeader.FileAlignment-1))
		setLoaderError(LDR_ERROR_FILE_ALIGNMENT_NOT_POW2);

	// Section alignment must not be 0
	if(optionalHeader.SectionAlignment == 0)
		setLoaderError(LDR_ERROR_SECTION_ALIGNMENT_ZERO);

	// Section alignment must be a power of 2
	if(optionalHeader.SectionAlignment & (optionalHeader.SectionAlignment - 1))
		setLoaderError(LDR_ERROR_SECTION_ALIGNMENT_NOT_POW2);

	if(optionalHeader.SectionAlignment < optionalHeader.FileAlignment)
		setLoaderError(LDR_ERROR_SECTION_ALIGNMENT_TOO_SMALL);

	// Check for images with "super-section": FileAlignment must be equal to SectionAlignment
	if((optionalHeader.FileAlignment & 511) && (optionalHeader.SectionAlignment != optionalHeader.FileAlignment))
		setLoaderError(LDR_ERROR_SECTION_ALIGNMENT_INVALID);

	// Check for largest image
	if(optionalHeader.SizeOfImage > PELIB_MM_SIZE_OF_LARGEST_IMAGE)
		setLoaderError(LDR_ERROR_SIZE_OF_IMAGE_TOO_BIG);

	// Check for 32-bit images
	if(optionalHeader.Magic == PELIB_IMAGE_NT_OPTIONAL_HDR32_MAGIC && checkForValid32BitMachine() == false)
		setLoaderError(LDR_ERROR_INVALID_MACHINE32);

	// Check for 64-bit images
	if(optionalHeader.Magic == PELIB_IMAGE_NT_OPTIONAL_HDR64_MAGIC && checkForValid64BitMachine() == false)
		setLoaderError(LDR_ERROR_INVALID_MACHINE64);

	// Check the size of image
	if(optionalHeader.SizeOfHeaders > optionalHeader.SizeOfImage)
		setLoaderError(LDR_ERROR_SIZE_OF_HEADERS_INVALID);

	// On 64-bit Windows, size of optional header must be properly aligned to 8-byte boundary
	if(is64BitWindows && (fileHeader.SizeOfOptionalHeader & 0x07))
		setLoaderError(LDR_ERROR_SIZE_OF_OPTHDR_NOT_ALIGNED);

	// Set the size of image
	if(BytesToPages(optionalHeader.SizeOfImage) == 0)
		setLoaderError(LDR_ERROR_SIZE_OF_IMAGE_ZERO);

	// Check for proper alignment of the image base
	if(optionalHeader.ImageBase & (PELIB_SIZE_64KB - 1))
		setLoaderError(LDR_ERROR_IMAGE_BASE_NOT_ALIGNED);

	return ERROR_NONE;
}

int PeLib::ImageLoader::saveNtHeadersNew(
	std::ostream & fs,
	std::streamoff fileOffset)
{
	// Calculate the size of the optional header. Any version of PE file,
	// 32 or 64-bit, must have this field set to a correct value.
	std::uint32_t sizeOfOptionalHeader = getFieldOffset(PELIB_MEMBER_TYPE::OPTHDR_sizeof_fixed) + optionalHeader.NumberOfRvaAndSizes * sizeof(PELIB_IMAGE_DATA_DIRECTORY);

	// Move to the required file offset
	fs.seekp(fileOffset, std::ios::beg);

	// Write the NT signature
	fs.write(reinterpret_cast<char *>(&ntSignature), sizeof(ntSignature));

	// Write the file header
	fileHeader.SizeOfOptionalHeader = sizeOfOptionalHeader;
	fileHeader.NumberOfSections = (std::uint16_t)sections.size();
	fs.write(reinterpret_cast<char *>(&fileHeader), sizeof(PELIB_IMAGE_FILE_HEADER));

	// Write the optional header. Note that we need to distinguish 32-bit and 64-bit header
	if(optionalHeader.Magic == PELIB_IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		PELIB_IMAGE_OPTIONAL_HEADER32 optionalHeader32;

		// Verify some of the data to make sure they are able to convert to 32-bit values
		if((optionalHeader.ImageBase >> 0x20) != 0)
			return ERROR_INVALID_FILE;
		if((optionalHeader.SizeOfStackReserve >> 0x20) != 0)
			return ERROR_INVALID_FILE;
		if((optionalHeader.SizeOfHeapReserve >> 0x20) != 0)
			return ERROR_INVALID_FILE;

		// Convert the optional header to 32-bit variant
		optionalHeader32.Magic                       = optionalHeader.Magic;
		optionalHeader32.MajorLinkerVersion          = optionalHeader.MajorLinkerVersion;
		optionalHeader32.MinorLinkerVersion          = optionalHeader.MinorLinkerVersion;
		optionalHeader32.SizeOfCode                  = optionalHeader.SizeOfCode;
		optionalHeader32.SizeOfInitializedData       = optionalHeader.SizeOfInitializedData;
		optionalHeader32.SizeOfUninitializedData     = optionalHeader.SizeOfUninitializedData;
		optionalHeader32.AddressOfEntryPoint         = optionalHeader.AddressOfEntryPoint;
		optionalHeader32.BaseOfCode                  = optionalHeader.BaseOfCode;
		optionalHeader32.BaseOfData                  = optionalHeader.BaseOfData;
		optionalHeader32.ImageBase                   = (std::uint32_t)optionalHeader.ImageBase;
		optionalHeader32.SectionAlignment            = optionalHeader.SectionAlignment;
		optionalHeader32.FileAlignment               = optionalHeader.FileAlignment;
		optionalHeader32.MajorOperatingSystemVersion = optionalHeader.MajorOperatingSystemVersion;
		optionalHeader32.MinorOperatingSystemVersion = optionalHeader.MinorOperatingSystemVersion;
		optionalHeader32.MajorImageVersion           = optionalHeader.MajorImageVersion;
		optionalHeader32.MinorImageVersion           = optionalHeader.MinorImageVersion;
		optionalHeader32.MajorSubsystemVersion       = optionalHeader.MajorSubsystemVersion;
		optionalHeader32.MinorSubsystemVersion       = optionalHeader.MinorSubsystemVersion;
		optionalHeader32.Win32VersionValue           = optionalHeader.Win32VersionValue;
		optionalHeader32.SizeOfImage                 = optionalHeader.SizeOfImage;
		optionalHeader32.SizeOfHeaders               = optionalHeader.SizeOfHeaders;
		optionalHeader32.CheckSum                    = optionalHeader.CheckSum;
		optionalHeader32.Subsystem                   = optionalHeader.Subsystem;
		optionalHeader32.DllCharacteristics          = optionalHeader.DllCharacteristics;
		optionalHeader32.SizeOfStackReserve          = (std::uint32_t)optionalHeader.SizeOfStackReserve;
		optionalHeader32.SizeOfStackCommit           = (std::uint32_t)optionalHeader.SizeOfStackCommit;
		optionalHeader32.SizeOfHeapReserve           = (std::uint32_t)optionalHeader.SizeOfHeapReserve;
		optionalHeader32.SizeOfHeapCommit            = (std::uint32_t)optionalHeader.SizeOfHeapCommit;
		optionalHeader32.LoaderFlags                 = optionalHeader.LoaderFlags;
		optionalHeader32.NumberOfRvaAndSizes         = optionalHeader.NumberOfRvaAndSizes;
		memcpy(&optionalHeader32.DataDirectory, &optionalHeader.DataDirectory, sizeof(optionalHeader.DataDirectory));

		// Write to file
		fs.write(reinterpret_cast<char *>(&optionalHeader32), sizeOfOptionalHeader);
	}
	else
	{
		PELIB_IMAGE_OPTIONAL_HEADER64 optionalHeader64;

		// Convert the optional header to 64-bit variant
		optionalHeader64.Magic                       = optionalHeader.Magic;
		optionalHeader64.MajorLinkerVersion          = optionalHeader.MajorLinkerVersion;
		optionalHeader64.MinorLinkerVersion          = optionalHeader.MinorLinkerVersion;
		optionalHeader64.SizeOfCode                  = optionalHeader.SizeOfCode;
		optionalHeader64.SizeOfInitializedData       = optionalHeader.SizeOfInitializedData;
		optionalHeader64.SizeOfUninitializedData     = optionalHeader.SizeOfUninitializedData;
		optionalHeader64.AddressOfEntryPoint         = optionalHeader.AddressOfEntryPoint;
		optionalHeader64.BaseOfCode                  = optionalHeader.BaseOfCode;
		optionalHeader64.ImageBase                   = optionalHeader.ImageBase;
		optionalHeader64.SectionAlignment            = optionalHeader.SectionAlignment;
		optionalHeader64.FileAlignment               = optionalHeader.FileAlignment;
		optionalHeader64.MajorOperatingSystemVersion = optionalHeader.MajorOperatingSystemVersion;
		optionalHeader64.MinorOperatingSystemVersion = optionalHeader.MinorOperatingSystemVersion;
		optionalHeader64.MajorImageVersion           = optionalHeader.MajorImageVersion;
		optionalHeader64.MinorImageVersion           = optionalHeader.MinorImageVersion;
		optionalHeader64.MajorSubsystemVersion       = optionalHeader.MajorSubsystemVersion;
		optionalHeader64.MinorSubsystemVersion       = optionalHeader.MinorSubsystemVersion;
		optionalHeader64.Win32VersionValue           = optionalHeader.Win32VersionValue;
		optionalHeader64.SizeOfImage                 = optionalHeader.SizeOfImage;
		optionalHeader64.SizeOfHeaders               = optionalHeader.SizeOfHeaders;
		optionalHeader64.CheckSum                    = optionalHeader.CheckSum;
		optionalHeader64.Subsystem                   = optionalHeader.Subsystem;
		optionalHeader64.DllCharacteristics          = optionalHeader.DllCharacteristics;
		optionalHeader64.SizeOfStackReserve          = optionalHeader.SizeOfStackReserve;
		optionalHeader64.SizeOfStackCommit           = optionalHeader.SizeOfStackCommit;
		optionalHeader64.SizeOfHeapReserve           = optionalHeader.SizeOfHeapReserve;
		optionalHeader64.SizeOfHeapCommit            = optionalHeader.SizeOfHeapCommit;
		optionalHeader64.LoaderFlags                 = optionalHeader.LoaderFlags;
		optionalHeader64.NumberOfRvaAndSizes         = optionalHeader.NumberOfRvaAndSizes;
		memcpy(&optionalHeader64.DataDirectory, &optionalHeader.DataDirectory, sizeof(optionalHeader64.DataDirectory));

		// Write to file
		fs.write(reinterpret_cast<char *>(&optionalHeader64), sizeOfOptionalHeader);
	}

	return ERROR_NONE;
}

int PeLib::ImageLoader::saveNtHeaders(
	std::ostream & fs,
	std::streamoff fileOffset)
{
	// Calculate the size of the optional header. Any version of PE file,
	// 32 or 64-bit, must have this field set to a correct value.
	std::size_t sizeOfOptionalHeader = getFieldOffset(PELIB_MEMBER_TYPE::OPTHDR_sizeof_fixed) + optionalHeader.NumberOfRvaAndSizes * sizeof(PELIB_IMAGE_DATA_DIRECTORY);
	std::size_t sizeOfHeaders = sizeof(std::uint32_t) + sizeof(PELIB_IMAGE_FILE_HEADER) + sizeOfOptionalHeader;

	// Give the size of NT headers some reasonable maximum
	if(sizeOfHeaders > PELIB_PAGE_SIZE * 10)
		return ERROR_INVALID_FILE;
	return saveToFile(fs, fileOffset, dosHeader.e_lfanew, sizeOfHeaders);
}

int PeLib::ImageLoader::captureSectionName(
	ByteBuffer & fileData,
	std::string & sectionName,
	const std::uint8_t * Name)
{
	// If the section name is in format of "/12345", then the section name is actually in the symbol table
	// Sample: 2e9c671b8a0411f2b397544b368c44d7f095eb395779de0ad1ac946914dfa34c
	if(fileHeader.PointerToSymbolTable != 0 && Name[0] == '/')
	{
		// Get the offset of the string table
		std::uint32_t stringTableOffset = fileHeader.PointerToSymbolTable + fileHeader.NumberOfSymbols * PELIB_IMAGE_SIZEOF_COFF_SYMBOL;
		std::uint32_t stringTableIndex = 0;

		// Convert the index from string to number
		for (std::size_t i = 1; i < PELIB_IMAGE_SIZEOF_SHORT_NAME && isdigit(Name[i]); i++)
			stringTableIndex = (stringTableIndex * 10) + (Name[i] - '0');

		// Get the section name
		if(readStringRaw(fileData, sectionName, stringTableOffset + stringTableIndex, PELIB_IMAGE_SIZEOF_MAX_NAME, true, true) != 0)
		    return ERROR_NONE;
	}

	// The section name is directly in the section header.
	// It has fixed length and must not be necessarily terminated with zero.
	sectionName.clear();

	// rstrip trailing nulls
	const std::uint8_t* end = Name + PELIB_IMAGE_SIZEOF_SHORT_NAME;
	// find the first non-null from end
	do
	{
		end--;
	} while (end - Name > 0 && *end == 0);

	if (end - Name > 0)
	{
		sectionName.assign(Name, end + 1);
	}

	return ERROR_NONE;
}

int PeLib::ImageLoader::captureSectionHeaders(ByteBuffer & fileData)
{
	std::uint8_t * fileBegin = fileData.data();
	std::uint8_t * filePtr;
	std::uint8_t * fileEnd = fileBegin + fileData.size();
	bool bRawDataBeyondEOF = false;

	// If there are no sections, then we're done
	if(fileHeader.NumberOfSections == 0)
		return ERROR_NONE;

	// Check whether the sections are within the file
	filePtr = fileBegin + dosHeader.e_lfanew + sizeof(std::uint32_t) + sizeof(PELIB_IMAGE_FILE_HEADER) + fileHeader.SizeOfOptionalHeader;
	if(filePtr > fileEnd)
		return setLoaderError(LDR_ERROR_SECTION_HEADERS_OUT_OF_IMAGE);

	// Set the counters
	std::uint32_t NumberOfSectionPTEs = AlignToSize(optionalHeader.SizeOfHeaders, optionalHeader.SectionAlignment) / PELIB_PAGE_SIZE;
	std::uint64_t NextVirtualAddress = 0;
	std::uint32_t NumberOfPTEs = BytesToPages(optionalHeader.SizeOfImage);
	std::uint32_t FileAlignmentMask = optionalHeader.FileAlignment - 1;
	bool SingleSubsection = (optionalHeader.SectionAlignment < PELIB_PAGE_SIZE);

	// Verify the image
	if(!SingleSubsection)
	{
		// Some extra checks done by the loader
		if((optionalHeader.SizeOfHeaders + (optionalHeader.SectionAlignment - 1)) < optionalHeader.SizeOfHeaders)
			setLoaderError(LDR_ERROR_SECTION_HEADERS_OVERFLOW);

		if(NumberOfSectionPTEs > NumberOfPTEs)
			setLoaderError(LDR_ERROR_SIZE_OF_HEADERS_INVALID);

		// Update the virtual address
		NextVirtualAddress += NumberOfSectionPTEs * PELIB_PAGE_SIZE;
		NumberOfPTEs -= NumberOfSectionPTEs;
	}
	else
	{
		NumberOfSectionPTEs = AlignToSize(optionalHeader.SizeOfImage, PELIB_PAGE_SIZE) / PELIB_PAGE_SIZE;
		NumberOfPTEs -= NumberOfSectionPTEs;
	}

	// Read and verify all section headers
	for(std::uint16_t i = 0; i < fileHeader.NumberOfSections; i++)
	{
		PELIB_SECTION_HEADER sectHdr;

		// Capture one section header
		if((filePtr + sizeof(PELIB_IMAGE_SECTION_HEADER)) > fileEnd)
			break;
		memcpy(&sectHdr, filePtr, sizeof(PELIB_IMAGE_SECTION_HEADER));

		// Fix the section header *in the source data*. We need to do that *after* the section header was loaded
		processSectionHeader((PELIB_IMAGE_SECTION_HEADER *)filePtr);

		// Parse the section headers and check for corruptions
		std::uint32_t PointerToRawData = (sectHdr.SizeOfRawData != 0) ? sectHdr.PointerToRawData : 0;
		std::uint32_t EndOfRawData = PointerToRawData + sectHdr.SizeOfRawData;
		std::uint32_t VirtualSize = (sectHdr.VirtualSize != 0) ? sectHdr.VirtualSize : sectHdr.SizeOfRawData;

		// Overflow check
		if((PointerToRawData + sectHdr.SizeOfRawData) < PointerToRawData)
			setLoaderError(LDR_ERROR_RAW_DATA_OVERFLOW);

		// Verify the image
		if(SingleSubsection)
		{
			// If the image is mapped as single subsection,
			// then the virtual values must match raw values
			if((sectHdr.VirtualAddress != sectHdr.PointerToRawData) || sectHdr.SizeOfRawData < VirtualSize)
				setLoaderError(LDR_ERROR_SECTION_SIZE_MISMATCH);
		}
		else
		{
			// Check the virtual address of the section
			if(NextVirtualAddress != sectHdr.VirtualAddress)
				setLoaderError(LDR_ERROR_INVALID_SECTION_VA);

			// Check the end of the section
			if((NextVirtualAddress + VirtualSize) <= NextVirtualAddress)
				setLoaderError(LDR_ERROR_INVALID_SECTION_VSIZE);

			// Check section size
			if((VirtualSize + (PELIB_PAGE_SIZE - 1)) <= VirtualSize)
				setLoaderError(LDR_ERROR_INVALID_SECTION_VSIZE);

			// Calculate number of PTEs in the section
			NumberOfSectionPTEs = AlignToSize(VirtualSize, optionalHeader.SectionAlignment) / PELIB_PAGE_SIZE;
			if(NumberOfSectionPTEs > NumberOfPTEs)
				setLoaderError(LDR_ERROR_INVALID_SECTION_VSIZE);

			NumberOfPTEs -= NumberOfSectionPTEs;

			// Check end of the raw data for the section
			if(((PointerToRawData + sectHdr.SizeOfRawData + FileAlignmentMask) & ~FileAlignmentMask) < PointerToRawData)
				setLoaderError(LDR_ERROR_INVALID_SECTION_RAWSIZE);

			// On last section, size of raw data must not go after the end of the file
			// Sample: a5957dad4b3a53a5894708c7c1ba91be0668ecbed49e33affee3a18c0737c3a5
			if(i == fileHeader.NumberOfSections - 1 && sectHdr.SizeOfRawData != 0)
			{
				if((sectHdr.PointerToRawData + sectHdr.SizeOfRawData) > fileData.size())
					setLoaderError(LDR_ERROR_FILE_IS_CUT);
			}

			NextVirtualAddress += NumberOfSectionPTEs * PELIB_PAGE_SIZE;
		}

		// Check for raw data beyond end-of-file
		// Note that Windows loader doesn't check this on files that are mapped as single section.
		// We will do that nonetheless, because we want to know that a file is cut.
		if(PointerToRawData != 0 && (fileBegin + EndOfRawData) > fileEnd)
			bRawDataBeyondEOF = true;

		// Resolve the section name
		captureSectionName(fileData, sectHdr.sectionName, sectHdr.Name);

		// Insert the header to the list
		sections.push_back(sectHdr);
		filePtr += sizeof(PELIB_IMAGE_SECTION_HEADER);
	}

	// Verify the image size. Note that this check is no longer performed by Windows 10
	if(sizeofImageMustMatch)
	{
		std::uint32_t ThresholdNumberOfPTEs = (SingleSubsection == false) ? (optionalHeader.SectionAlignment / PELIB_PAGE_SIZE) : 1;
		if(NumberOfPTEs >= ThresholdNumberOfPTEs)
		{
			setLoaderError(LDR_ERROR_INVALID_SIZE_OF_IMAGE);
		}
	}

	// Did we detect a trimmed file?
	if(bRawDataBeyondEOF)
	{
		// Track the state of loadability of the cut file. Some files can still be loadable.
		// Example: bd149478739e660b032e4454057ce8d3e18dfbb6d1677c6ecdcc3aa59b36c8d9
		bool bCutButLoadable = false;

		// Special exception: Even if cut, the file is still loadable
		// if the last section is in the file range. This is because
		// the PE loader in Windows only cares about whether the last section is in the file range
		if(SingleSubsection == false)
		{
			if(!sections.empty())
			{
				PELIB_IMAGE_SECTION_HEADER & lastSection = sections.back();
				std::uint32_t PointerToRawData = (lastSection.SizeOfRawData != 0) ? lastSection.PointerToRawData : 0;
				std::uint32_t EndOfRawData = PointerToRawData + lastSection.SizeOfRawData;

				if((lastSection.SizeOfRawData == 0) || (fileBegin + EndOfRawData) <= fileEnd)
				{
					setLoaderError(LDR_ERROR_FILE_IS_CUT_LOADABLE);
					bCutButLoadable = true;
				}
			}
		}
		else
		{
			setLoaderError(LDR_ERROR_FILE_IS_CUT_LOADABLE);
			bCutButLoadable = true;
		}

		// If the file is not loadable, set the "file is cut" error
		if(bCutButLoadable == false)
		{
			setLoaderError(LDR_ERROR_FILE_IS_CUT);
		}
	}

	return ERROR_NONE;
}

int PeLib::ImageLoader::saveSectionHeadersNew(
	std::ostream & fs,
	std::streamoff fileOffset)
{
	PELIB_IMAGE_SECTION_HEADER * pHeaders;
	std::size_t sectionCount = sections.size();
	std::size_t index = 0;

	if((pHeaders = new PELIB_IMAGE_SECTION_HEADER[sectionCount]) != nullptr)
	{
		// Populate the array with section headers
		for(const auto & section : sections)
		{
			memcpy(pHeaders + index, section.Name, sizeof(PELIB_IMAGE_SECTION_HEADER));
			index++;
		}

		// Write the section headers to file
		fs.seekp(fileOffset, std::ios::beg);
		fs.write(reinterpret_cast<char *>(pHeaders), sectionCount * sizeof(PELIB_IMAGE_SECTION_HEADER));
		delete[] pHeaders;
	}

	return ERROR_NONE;
}

int PeLib::ImageLoader::saveSectionHeaders(
	std::ostream & fs,
	std::streamoff fileOffset)
{
	std::size_t offsetOfHeaders = dosHeader.e_lfanew + sizeof(std::uint32_t) + sizeof(PELIB_IMAGE_FILE_HEADER) + fileHeader.SizeOfOptionalHeader;
	std::size_t sizeOfHeaders = fileHeader.NumberOfSections * sizeof(PELIB_IMAGE_SECTION_HEADER);

	// Give the size of NT headers some reasonable maximum
	if(sizeOfHeaders > PELIB_PAGE_SIZE * 10)
		return ERROR_INVALID_FILE;
	return saveToFile(fs, fileOffset, offsetOfHeaders, sizeOfHeaders);
}

int PeLib::ImageLoader::captureImageSections(ByteBuffer & fileData, std::uint32_t loadFlags)
{
	std::uint32_t virtualAddress = 0;
	std::uint32_t sizeOfHeaders = optionalHeader.SizeOfHeaders;
	std::uint32_t sizeOfImage = optionalHeader.SizeOfImage;

	// Section-based mapping / file-based mapping
	if(optionalHeader.SectionAlignment >= PELIB_PAGE_SIZE)
	{
		// Reserve the image size, aligned up to the page size
		sizeOfImage = AlignToSize(sizeOfImage, PELIB_PAGE_SIZE);
		pages.resize(sizeOfImage / PELIB_PAGE_SIZE);

		// Note: Under Windows XP, the loader maps the entire page of the image header
		// if the condition in checkForSectionTablesWithinHeader() turns out to be true.
		// Windows 7+ uses correct size check.
		// Sample: 1669f0220f1f74523390fe5b61ea09d6e2e4e798ab294c93d0a20900a3c5a52a
		// (Any sample with 4 sections and IMAGE_DOS_HEADER::e_lfanew >= 0x724 will do)
		if(headerSizeCheck && checkForSectionTablesWithinHeader(dosHeader.e_lfanew))
			sizeOfHeaders = AlignToSize(sizeOfHeaders, optionalHeader.SectionAlignment);

		// Capture the file header
		virtualAddress = captureImageSection(fileData, virtualAddress, sizeOfHeaders, 0, sizeOfHeaders, PELIB_IMAGE_SCN_MEM_READ, true);
		if(virtualAddress == 0)
			return ERROR_INVALID_FILE;

		// Capture each section
		if(sections.size() != 0)
		{
			for(auto & sectionHeader : sections)
			{
				// If loading as image, we need to take data from its virtual address
				std::uint32_t pointerToRawData = (loadFlags & IoFlagLoadAsImage) ? sectionHeader.VirtualAddress : sectionHeader.PointerToRawData;
				std::uint32_t sectionEnd;

				// Capture all pages from the section
				sectionEnd = captureImageSection(fileData,
												 sectionHeader.VirtualAddress,
												 sectionHeader.VirtualSize,
												 pointerToRawData,
												 sectionHeader.SizeOfRawData,
												 sectionHeader.Characteristics);

				// There must not be a Virtual Address overflow,
				// nor the end of the section must be beyond the end of the image
				if(sectionEnd < sectionHeader.VirtualAddress || sectionEnd > sizeOfImage)
				{
					setLoaderError(LDR_ERROR_INVALID_SECTION_VSIZE);
					break;
				}
			}
		}
		else
		{
			// If the file has no sections, we need to check the SizeOfImage against
			// the virtual address. They must match, otherwise Windows will not load the file.
			// Sample: cdf2a3ff23ec8a0814e285d94c4f081202ea6fe69661ff9940dcafc28e5fc626
			if(virtualAddress > optionalHeader.SizeOfImage || (optionalHeader.SizeOfImage - virtualAddress) > optionalHeader.SectionAlignment)
			{
				setLoaderError(LDR_ERROR_INVALID_SIZE_OF_IMAGE);
			}
		}
	}
	else
	{
		// 64-bit Windows always align single-section images to page size.
		// 32-bit Windows:
		// * Windows XP: sector size
		// * Windows 7 : sector size (network files) or no align (local files)
		// * Windows 10: no align
		// If the image is smaller than one page, it is aligned to one page
		sizeOfImage = AlignToSize(sizeOfImage, ssiImageAlignment32);
		if(is64BitWindows && alignSingleSectionImagesToPage)
			sizeOfImage = AlignToSize(sizeOfImage, PELIB_PAGE_SIZE);
		if(sizeOfImage < PELIB_PAGE_SIZE)
			sizeOfImage = PELIB_PAGE_SIZE;
		pages.resize((sizeOfImage + PELIB_PAGE_SIZE - 1) / PELIB_PAGE_SIZE);

		// Capture the file as-is
		virtualAddress = captureImageSection(fileData, 0, sizeOfImage, 0, sizeOfImage, PELIB_IMAGE_SCN_MEM_WRITE | PELIB_IMAGE_SCN_MEM_READ | PELIB_IMAGE_SCN_MEM_EXECUTE, true);
		if(virtualAddress == 0)
			return ERROR_INVALID_FILE;
	}

	return ERROR_NONE;
}

int PeLib::ImageLoader::verifyDosHeader(
	PELIB_IMAGE_DOS_HEADER & hdr,
	std::size_t fileSize)
{
	if(hdr.e_magic != PELIB_IMAGE_DOS_SIGNATURE)
		return ERROR_INVALID_FILE;
	if(hdr.e_lfanew & 3)
		return setLoaderError(LDR_ERROR_E_LFANEW_UNALIGNED);
	if(hdr.e_lfanew > fileSize)
		return setLoaderError(LDR_ERROR_E_LFANEW_OUT_OF_FILE);

	return ERROR_NONE;
}

int PeLib::ImageLoader::verifyDosHeader(
	std::istream & fs,
	std::streamoff fileOffset,
	std::size_t fileSize)
{
	PELIB_IMAGE_DOS_HEADER tempDosHeader;
	int fileError;

	// The file size must be at least size of DOS header
	if((fileOffset + sizeof(PELIB_IMAGE_DOS_HEADER)) >= fileSize)
		return ERROR_INVALID_FILE;
	fs.seekg(fileOffset);

	// Read the DOS header
	if(fs.read(reinterpret_cast<char*>(&tempDosHeader), sizeof(PELIB_IMAGE_DOS_HEADER)).bad())
		return ERROR_INVALID_FILE;

	// Verify the DOS header
	if((fileError = verifyDosHeader(tempDosHeader, fileSize)) != ERROR_NONE)
		return fileError;

	// If the DOS header points out of the file, it's a wrong file too
	return (ldrError == LDR_ERROR_E_LFANEW_OUT_OF_FILE) ? ERROR_INVALID_FILE : ERROR_NONE;
}

int PeLib::ImageLoader::loadImageAsIs(ByteBuffer & fileData)
{
	rawFileData = fileData;
	return ERROR_NONE;
}

// While copying the data directories, we take into account possible out-of-bounds
// data directory entries, as long as they fit into sizeOfOptionalHeader
// Sample: 53b13d7cfb97b5475e21717397c85376a1de2b18c2eeb6532b160fb8aa3a393d
// This sample has NumberOfRvaAndSizes set to 0x0E, but the IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR (0x0E),
// but the .NET framework (_CorExeMain) does not care about NumberOfRvaAndSizes
// and directly takes the DataDirectory without checking NumberOfRvaAndSizes
std::uint32_t PeLib::ImageLoader::copyDataDirectories(
	std::uint8_t * optionalHeaderPtr,
	std::uint8_t * dataDirectoriesPtr,
	std::size_t optionalHeaderMax,			// How many bytes do we have from the beginning of the optional header till the end of the file
	std::uint32_t numberOfRvaAndSizes)
{
	std::uint8_t * dataDirectoriesEnd = dataDirectoriesPtr + PELIB_IMAGE_NUMBEROF_DIRECTORY_ENTRIES * sizeof(PELIB_IMAGE_DATA_DIRECTORY);

	// Do not leave numberOfRvaAndSizes higher than the maximum possible value
	if(numberOfRvaAndSizes > PELIB_IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
		numberOfRvaAndSizes = PELIB_IMAGE_NUMBEROF_DIRECTORY_ENTRIES;

	// Determine the end of data directories based on file size.
	// Note that the SizeOfOptionalHeader does NOT have any meaning in this
	if(dataDirectoriesEnd > (optionalHeaderPtr + optionalHeaderMax))
		dataDirectoriesEnd = (optionalHeaderPtr + optionalHeaderMax);

	// Copy data directories, up to SizeOfOptionalHeader
	if(dataDirectoriesEnd > dataDirectoriesPtr)
		memcpy(optionalHeader.DataDirectory, dataDirectoriesPtr, (dataDirectoriesEnd - dataDirectoriesPtr));
	return numberOfRvaAndSizes;
}

int PeLib::ImageLoader::captureOptionalHeader64(
	std::uint8_t * fileBegin,
	std::uint8_t * filePtr,
	std::uint8_t * fileEnd)
{
	PELIB_IMAGE_OPTIONAL_HEADER64 optionalHeader64{};
	std::uint32_t sizeOfOptionalHeader = sizeof(PELIB_IMAGE_OPTIONAL_HEADER64);

	// Capture optional header. Note that IMAGE_FILE_HEADER::SizeOfOptionalHeader
	// is not taken into account by the Windows loader - it simply assumes that the entire optional header is present
	if((filePtr + sizeOfOptionalHeader) > fileEnd)
		sizeOfOptionalHeader = (std::uint32_t)(fileEnd - filePtr);
	memcpy(&optionalHeader64, filePtr, sizeOfOptionalHeader);

	// Verify whether it's 64-bit optional header
	if(optionalHeader64.Magic != PELIB_IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		return setLoaderError(LDR_ERROR_NO_OPTHDR_MAGIC);

	// Convert 32-bit optional header to common optional header
	optionalHeader.Magic                       = optionalHeader64.Magic;
	optionalHeader.MajorLinkerVersion          = optionalHeader64.MajorLinkerVersion;
	optionalHeader.MinorLinkerVersion          = optionalHeader64.MinorLinkerVersion;
	optionalHeader.SizeOfCode                  = optionalHeader64.SizeOfCode;
	optionalHeader.SizeOfInitializedData       = optionalHeader64.SizeOfInitializedData;
	optionalHeader.SizeOfUninitializedData     = optionalHeader64.SizeOfUninitializedData;
	optionalHeader.AddressOfEntryPoint         = optionalHeader64.AddressOfEntryPoint;
	optionalHeader.BaseOfCode                  = optionalHeader64.BaseOfCode;
	optionalHeader.ImageBase                   = optionalHeader64.ImageBase;
	optionalHeader.SectionAlignment            = optionalHeader64.SectionAlignment;
	optionalHeader.FileAlignment               = optionalHeader64.FileAlignment;
	optionalHeader.MajorOperatingSystemVersion = optionalHeader64.MajorOperatingSystemVersion;
	optionalHeader.MinorOperatingSystemVersion = optionalHeader64.MinorOperatingSystemVersion;
	optionalHeader.MajorImageVersion           = optionalHeader64.MajorImageVersion;
	optionalHeader.MinorImageVersion           = optionalHeader64.MinorImageVersion;
	optionalHeader.MajorSubsystemVersion       = optionalHeader64.MajorSubsystemVersion;
	optionalHeader.MinorSubsystemVersion       = optionalHeader64.MinorSubsystemVersion;
	optionalHeader.Win32VersionValue           = optionalHeader64.Win32VersionValue;
	optionalHeader.SizeOfImage                 = optionalHeader64.SizeOfImage;
	optionalHeader.SizeOfHeaders               = optionalHeader64.SizeOfHeaders;
	optionalHeader.CheckSum                    = optionalHeader64.CheckSum;
	optionalHeader.Subsystem                   = optionalHeader64.Subsystem;
	optionalHeader.DllCharacteristics          = optionalHeader64.DllCharacteristics;
	optionalHeader.SizeOfStackReserve          = optionalHeader64.SizeOfStackReserve;
	optionalHeader.SizeOfStackCommit           = optionalHeader64.SizeOfStackCommit;
	optionalHeader.SizeOfHeapReserve           = optionalHeader64.SizeOfHeapReserve;
	optionalHeader.SizeOfHeapCommit            = optionalHeader64.SizeOfHeapCommit;
	optionalHeader.LoaderFlags                 = optionalHeader64.LoaderFlags;
	optionalHeader.NumberOfRvaAndSizes         = optionalHeader64.NumberOfRvaAndSizes;

	// Copy data directories
	realNumberOfRvaAndSizes = copyDataDirectories((std::uint8_t *)(&optionalHeader64),
												  (std::uint8_t *)(&optionalHeader64.DataDirectory[0]),
												  fileEnd - filePtr,
												  optionalHeader64.NumberOfRvaAndSizes);

	// Remember the offset of the checksum field
	checkSumFileOffset = (filePtr - fileBegin) + offsetof(PELIB_IMAGE_OPTIONAL_HEADER64, CheckSum);
	securityDirFileOffset = (filePtr - fileBegin) + offsetof(PELIB_IMAGE_OPTIONAL_HEADER64, DataDirectory) + (sizeof(PELIB_IMAGE_DATA_DIRECTORY) * PELIB_IMAGE_DIRECTORY_ENTRY_SECURITY);
	return ERROR_NONE;
}

int PeLib::ImageLoader::captureOptionalHeader32(
	std::uint8_t * fileBegin,
	std::uint8_t * filePtr,
	std::uint8_t * fileEnd)
{
	PELIB_IMAGE_OPTIONAL_HEADER32 optionalHeader32{};
	std::uint32_t sizeOfOptionalHeader = sizeof(PELIB_IMAGE_OPTIONAL_HEADER32);

	// Capture optional header. Note that IMAGE_FILE_HEADER::SizeOfOptionalHeader
	// is not taken into account by the Windows loader - it simply assumes that the entire optional header is present
	if((filePtr + sizeOfOptionalHeader) > fileEnd)
		sizeOfOptionalHeader = (std::uint32_t)(fileEnd - filePtr);
	memcpy(&optionalHeader32, filePtr, sizeOfOptionalHeader);

	// Note: Do not fail if there's no magic value for 32-bit optional header
	if(optionalHeader32.Magic != PELIB_IMAGE_NT_OPTIONAL_HDR32_MAGIC)
		setLoaderError(LDR_ERROR_NO_OPTHDR_MAGIC);

	// Convert 32-bit optional header to common optional header
	optionalHeader.Magic                       = optionalHeader32.Magic;
	optionalHeader.MajorLinkerVersion          = optionalHeader32.MajorLinkerVersion;
	optionalHeader.MinorLinkerVersion          = optionalHeader32.MinorLinkerVersion;
	optionalHeader.SizeOfCode                  = optionalHeader32.SizeOfCode;
	optionalHeader.SizeOfInitializedData       = optionalHeader32.SizeOfInitializedData;
	optionalHeader.SizeOfUninitializedData     = optionalHeader32.SizeOfUninitializedData;
	optionalHeader.AddressOfEntryPoint         = optionalHeader32.AddressOfEntryPoint;
	optionalHeader.BaseOfCode                  = optionalHeader32.BaseOfCode;
	optionalHeader.BaseOfData                  = optionalHeader32.BaseOfData;
	optionalHeader.ImageBase                   = optionalHeader32.ImageBase;
	optionalHeader.SectionAlignment            = optionalHeader32.SectionAlignment;
	optionalHeader.FileAlignment               = optionalHeader32.FileAlignment;
	optionalHeader.MajorOperatingSystemVersion = optionalHeader32.MajorOperatingSystemVersion;
	optionalHeader.MinorOperatingSystemVersion = optionalHeader32.MinorOperatingSystemVersion;
	optionalHeader.MajorImageVersion           = optionalHeader32.MajorImageVersion;
	optionalHeader.MinorImageVersion           = optionalHeader32.MinorImageVersion;
	optionalHeader.MajorSubsystemVersion       = optionalHeader32.MajorSubsystemVersion;
	optionalHeader.MinorSubsystemVersion       = optionalHeader32.MinorSubsystemVersion;
	optionalHeader.Win32VersionValue           = optionalHeader32.Win32VersionValue;
	optionalHeader.SizeOfImage                 = optionalHeader32.SizeOfImage;
	optionalHeader.SizeOfHeaders               = optionalHeader32.SizeOfHeaders;
	optionalHeader.CheckSum                    = optionalHeader32.CheckSum;
	optionalHeader.Subsystem                   = optionalHeader32.Subsystem;
	optionalHeader.DllCharacteristics          = optionalHeader32.DllCharacteristics;
	optionalHeader.SizeOfStackReserve          = optionalHeader32.SizeOfStackReserve;
	optionalHeader.SizeOfStackCommit           = optionalHeader32.SizeOfStackCommit;
	optionalHeader.SizeOfHeapReserve           = optionalHeader32.SizeOfHeapReserve;
	optionalHeader.SizeOfHeapCommit            = optionalHeader32.SizeOfHeapCommit;
	optionalHeader.LoaderFlags                 = optionalHeader32.LoaderFlags;
	optionalHeader.NumberOfRvaAndSizes         = optionalHeader32.NumberOfRvaAndSizes;

	// Copy data directories
	realNumberOfRvaAndSizes = copyDataDirectories((std::uint8_t *)(&optionalHeader32),
												  (std::uint8_t *)(&optionalHeader32.DataDirectory[0]),
												  fileEnd - filePtr,
												  optionalHeader32.NumberOfRvaAndSizes);

	// Remember the offset of the checksum field
	checkSumFileOffset = (filePtr - fileBegin) + offsetof(PELIB_IMAGE_OPTIONAL_HEADER32, CheckSum);
	securityDirFileOffset = (filePtr - fileBegin) + offsetof(PELIB_IMAGE_OPTIONAL_HEADER32, DataDirectory) + (sizeof(PELIB_IMAGE_DATA_DIRECTORY) * PELIB_IMAGE_DIRECTORY_ENTRY_SECURITY);
	return ERROR_NONE;
}

std::uint32_t PeLib::ImageLoader::captureImageSection(
	ByteBuffer & fileData,
	std::uint32_t virtualAddress,
	std::uint32_t virtualSize,
	std::uint32_t pointerToRawData,
	std::uint32_t sizeOfRawData,
	std::uint32_t characteristics,
	bool isImageHeader)
{
	std::uint8_t * fileBegin = fileData.data();
	std::uint8_t * rawDataPtr;
	std::uint8_t * rawDataEnd;
	std::uint8_t * fileEnd = fileBegin + fileData.size();
	std::uint32_t sizeOfInitializedPages;            // The part of section with initialized pages
	std::uint32_t sizeOfValidPages;                  // The part of section with valid pages
	std::uint32_t sizeOfSection;                     // Total virtual size of the section
	std::uint32_t pageOffset = 0;
	std::size_t pageIndex;

	// If the virtual size of a section is zero, take the size of raw data
	virtualSize = (virtualSize == 0) ? sizeOfRawData : virtualSize;

	// Virtual size is aligned to PAGE_SIZE (not SectionAlignment!)
	// If SectionAlignment > PAGE_SIZE, header and sections are padded with invalid pages (PAGE_NOACCESS)
	// Sample: f73e66052c8b0a49d56ccadcecdf497c015b5ec6f6724e056f35b57b59afaf59
	virtualSize = AlignToSize(virtualSize, PELIB_PAGE_SIZE);

	// If SizeOfRawData is greater than VirtualSize, cut it to virtual size
	// Note that up to the aligned virtual size, the data are in the section
	if(sizeOfRawData > virtualSize)
		sizeOfRawData = virtualSize;

	// If SectionAlignment is greater than page size, then there are going to be
	// gaps of inaccessible memory after the end of raw data
	// Example: b811f2c047a3e828517c234bd4aa4883e1ec591d88fad21289ae68a6915a6665
	// * has 0x1000 bytes of inaccessible memory at ImageBase+0x1000 (1 page after section header)
	sizeOfInitializedPages = AlignToSize(sizeOfRawData, PELIB_PAGE_SIZE);
	sizeOfValidPages = AlignToSize(virtualSize, PELIB_PAGE_SIZE);

	// Calculate aligned size of the section. Mind invalid sizes.
	// Example: 83e9cb2a6e78c742e1090292acf3c78baf76e82950d96548673795a1901db061
	// * Size of the last section is 0xfffff000, sizeOfSection becomes 0
	sizeOfSection = AlignToSize(virtualSize, optionalHeader.SectionAlignment);
	if(sizeOfSection < virtualSize)
		sizeOfSection = virtualSize;

	// Get the range of the file containing valid data (aka nonzeros)
	// Pointer to raw data is aligned down to the sector size
	// due to the Windows Loader logic that sets sector offset in the page table entries
	rawDataPtr = fileBegin + (pointerToRawData & ~(PELIB_SECTOR_SIZE - 1));
	rawDataEnd = rawDataPtr + sizeOfRawData;

	// End of raw data is aligned to the file alignment. This does not apply to image header
	// Sample: ab0a9c4a8beee49a13cbf6c684b58f9604d673c9d5522a73ec5dffda909695a1
	// SizeOfHeaders = 0x400, FileAlignment = 0x1000. Only 0x400 bytes is copied to the image
	if(isImageHeader == false)
		rawDataEnd = fileBegin + AlignToSize(pointerToRawData + sizeOfRawData, optionalHeader.FileAlignment);

	// Virtual address must begin exactly at the end of previous VA
	pageIndex = virtualAddress / PELIB_PAGE_SIZE;

	// Some combination of flags in IMAGE_SECTION_HEADER::Characteristics give PAGE_NOACCESS
	// If the image is mapped with SEC_IMAGE_NO_EXECUTE (Windows 10),
	// some of the NOACCESS sections turn into READONLY sections.
	if(getImageProtection(characteristics) != PELIB_PAGE_NOACCESS)
	{
		// If the pointerToRawData is less than SECTOR_SIZE, it will contain file header in it.
		// However, if the pointerToRawData contains 0, then the
		if(pointerToRawData || isImageHeader)
		{
			// Fill all pages that contain data
			while(pageOffset < sizeOfInitializedPages && pageIndex < pages.size())
			{
				PELIB_FILE_PAGE & filePage = pages[pageIndex++];

				// Only if we didn't get out of the file
				if(rawDataPtr < fileEnd)
				{
					std::size_t bytesToCopy = PELIB_PAGE_SIZE;

					// Check range validity
					if((rawDataPtr + bytesToCopy) > fileEnd)
						bytesToCopy = (fileEnd - rawDataPtr);
					if((rawDataPtr + bytesToCopy) > rawDataEnd)
						bytesToCopy = (rawDataEnd - rawDataPtr);

					// Initialize the page with valid data
					filePage.setValidPage(rawDataPtr, bytesToCopy);
				}
				else
				{
					filePage.setZeroPage();
				}

				// Move pointers
				rawDataPtr += PELIB_PAGE_SIZE;
				pageOffset += PELIB_PAGE_SIZE;
			}
		}

		// Fill all pages that contain zeroed pages
		while(pageOffset < sizeOfValidPages && pageIndex < pages.size())
		{
			PELIB_FILE_PAGE & filePage = pages[pageIndex++];

			filePage.setZeroPage();
			pageOffset += PELIB_PAGE_SIZE;
		}
	}

	// Leave all other pages filled with zeros
	return virtualAddress + sizeOfSection;
}

bool PeLib::ImageLoader::isGoodPagePointer(
	PFN_VERIFY_ADDRESS PfnVerifyAddress,
	void * pagePtr)
{
	// If the caller didn't supply a verification procedure, use default one
	// The verification procedure can possibly be system-specific, like IsBadReadPtr on Windows
	if(PfnVerifyAddress == nullptr)
	{
		// In order to work in Windows, it must be built with /EHa
		// (Enable C++ Exceptions: Yes with SEH Exceptions (/EHa))
		try
		{
			std::uint8_t dummyBuffer[0x10] = {0};
			memcmp(pagePtr, dummyBuffer, sizeof(dummyBuffer));
			return true;
		}
		catch(...)
		{
			return false;
		}
	}
	else
	{
		return PfnVerifyAddress(pagePtr, PELIB_PAGE_SIZE);
	}
}

bool PeLib::ImageLoader::isGoodMappedPage(std::uint32_t rva)
{
	std::uint32_t pageIndex = (rva / PELIB_PAGE_SIZE);

	return (pageIndex < pages.size()) ? !pages[pageIndex].isInvalidPage : false;
}

bool PeLib::ImageLoader::isZeroPage(std::uint32_t rva)
{
	std::uint32_t pageIndex = (rva / PELIB_PAGE_SIZE);

	return (pageIndex < pages.size()) ? pages[pageIndex].isZeroPage : false;
}

bool PeLib::ImageLoader::isSectionHeaderPointerToRawData(std::uint32_t fileOffset)
{
	std::uint32_t fileOffsetToSectionHeader = dosHeader.e_lfanew + sizeof(std::uint32_t) + sizeof(PELIB_IMAGE_FILE_HEADER) + fileHeader.SizeOfOptionalHeader;
	std::uint32_t fileOffsetOfPointerToRawData;

	// If there is at least one section
	for(std::size_t i = 0; i < sections.size(); i++, fileOffsetToSectionHeader += sizeof(PELIB_IMAGE_SECTION_HEADER))
	{
		// Get the reference to the section header
		PELIB_IMAGE_SECTION_HEADER & sectHdr = sections[i];

		// Must be a section with SizeOfRawData = 0
		if(sectHdr.SizeOfRawData == 0)
		{
			// Calculate the RVA of the PointerToRawData variable in the last section
			fileOffsetOfPointerToRawData = fileOffsetToSectionHeader + 0x14;  // FIELD_OFFSET(PELIB_IMAGE_SECTION_HEADER, PointerToRawData)

			if(fileOffsetOfPointerToRawData <= fileOffset && fileOffset < fileOffsetOfPointerToRawData + sizeof(std::uint32_t))
				return true;
		}
	}

	return false;
}

// MiIsLegacyImageArchitecture from Windows 10
bool PeLib::ImageLoader::isLegacyImageArchitecture(std::uint16_t Machine)
{
	if(Machine == PELIB_IMAGE_FILE_MACHINE_I386)
		return true;
	if(Machine == PELIB_IMAGE_FILE_MACHINE_AMD64)
		return true;
	return false;
}

bool PeLib::ImageLoader::checkForValid64BitMachine()
{
	if(loadItaniumImages && fileHeader.Machine == PELIB_IMAGE_FILE_MACHINE_IA64)
		return true;
	if(loadArm64Images && fileHeader.Machine == PELIB_IMAGE_FILE_MACHINE_ARM64)
		return true;
	return (fileHeader.Machine == PELIB_IMAGE_FILE_MACHINE_AMD64);
}

bool PeLib::ImageLoader::checkForValid32BitMachine()
{
	if(loadArmImages && fileHeader.Machine == PELIB_IMAGE_FILE_MACHINE_ARMNT)
		return true;
	return (fileHeader.Machine == PELIB_IMAGE_FILE_MACHINE_I386);
}

bool PeLib::ImageLoader::checkForInvalidImageRange()
{
	// Only do the check for 32-bit images
	if(optionalHeader.Magic == PELIB_IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		std::uint64_t MmHighestUserAddress = 0x7FFEFFFF;
		std::uint64_t MmHighestImageBase = MmHighestUserAddress - 0x10000;
		std::uint64_t MmLowestImageBase = 0x00010000;
		std::uint64_t ImageBase = optionalHeader.ImageBase;
		std::uint32_t AlignedSizeOfImage = AlignToSize(optionalHeader.SizeOfImage, PELIB_PAGE_SIZE);

		// If any part of the image goes out of the allowed range, it's invalid
		// Windows will do the same check and relocate the image if possible
		if(ImageBase < MmLowestImageBase || ImageBase > MmHighestImageBase || (ImageBase + AlignedSizeOfImage) > MmHighestImageBase)
		{
			return true;
		}
	}

	return false;
}

bool PeLib::ImageLoader::isValidMachineForCodeIntegrifyCheck(std::uint32_t Bits)
{
	if(Bits & 64)
	{
		// AMD64 is always allowed
		if(fileHeader.Machine == PELIB_IMAGE_FILE_MACHINE_AMD64)
			return true;

		// Returns STATUS_INVALID_IMAGE_FORMAT due to page size being 0x2000
		if(fileHeader.Machine == PELIB_IMAGE_FILE_MACHINE_IA64)
			return true;

		if(fileHeader.Machine == PELIB_IMAGE_FILE_MACHINE_ARM64)
			return true;
	}

	if(Bits & 32)
	{
		// Any of these is allowed
		if(fileHeader.Machine == PELIB_IMAGE_FILE_MACHINE_I386 || fileHeader.Machine == PELIB_IMAGE_FILE_MACHINE_ARM)
			return true;

		// Since Windows 8, IMAGE_FILE_MACHINE_ARMNT is alowed here as well
		if(loadArmImages && fileHeader.Machine == PELIB_IMAGE_FILE_MACHINE_ARMNT)
			return true;
	}

	return false;
}

// Windows Vista+: If IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY is set,
// there are some more checks implemented by CI!HashpParsePEHeader
// (nt!SeValidateImageHeader -> CI!CiValidateImageHeader -> ... -> CI!HashpParsePEHeader in Win7)
// This function does the same checks like CI!HashpParsePEHeader
bool PeLib::ImageLoader::checkForBadCodeIntegrityImages(ByteBuffer & fileData)
{
	if(optionalHeader.DllCharacteristics & PELIB_IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY)
	{
		PELIB_IMAGE_DATA_DIRECTORY & SecurityDir = optionalHeader.DataDirectory[PELIB_IMAGE_DIRECTORY_ENTRY_SECURITY];
		std::uint32_t sizeOfNtHeaders = sizeof(std::uint32_t) + sizeof(PELIB_IMAGE_FILE_HEADER) + sizeof(PELIB_IMAGE_OPTIONAL_HEADER32);
		std::uint32_t endOfRawData;
		std::size_t peFileSize = fileData.size();

		if(dosHeader.e_lfanew < sizeof(PELIB_IMAGE_DOS_HEADER))
			return true;
		if(dosHeader.e_lfanew > optionalHeader.SectionAlignment)
			return true;
		if((optionalHeader.SectionAlignment - dosHeader.e_lfanew) <= dosHeader.e_lfanew)
			return true;
		if((dosHeader.e_lfanew + sizeOfNtHeaders) > optionalHeader.SectionAlignment)
			return true;

		if(ntSignature != PELIB_IMAGE_NT_SIGNATURE)
			return true;
		if(fileHeader.SizeOfOptionalHeader == 0)
			return true;

		if(!isValidMachineForCodeIntegrifyCheck(32 | 64))
			return true;

		if(optionalHeader.MajorLinkerVersion < 3 && optionalHeader.MajorLinkerVersion < 5)
			return true;
		if(optionalHeader.Magic != PELIB_IMAGE_NT_OPTIONAL_HDR32_MAGIC && optionalHeader.Magic != PELIB_IMAGE_NT_OPTIONAL_HDR64_MAGIC)
			return true;

		// Check whether there is match between bitness of the optional header and machine
		if(optionalHeader.Magic == PELIB_IMAGE_NT_OPTIONAL_HDR32_MAGIC && !isValidMachineForCodeIntegrifyCheck(32))
			return true;
		if(optionalHeader.Magic == PELIB_IMAGE_NT_OPTIONAL_HDR64_MAGIC && !isValidMachineForCodeIntegrifyCheck(64))
			return true;

		if(optionalHeader.SizeOfHeaders == 0 || optionalHeader.SizeOfHeaders > peFileSize)
			return true;
		if(optionalHeader.FileAlignment == 0 || (optionalHeader.FileAlignment & (optionalHeader.FileAlignment - 1)))
			return true;
		if(optionalHeader.SectionAlignment & (optionalHeader.SectionAlignment - 1))
			return true;
		if(optionalHeader.FileAlignment > optionalHeader.SectionAlignment)
			return true;
		if((optionalHeader.FileAlignment & (PELIB_SECTOR_SIZE - 1)) && (optionalHeader.FileAlignment != optionalHeader.SectionAlignment))
			return true;

		// End of headers altogether must fit in the first page
		endOfRawData = dosHeader.e_lfanew + sizeof(std::uint32_t) + sizeof(PELIB_IMAGE_FILE_HEADER) + fileHeader.SizeOfOptionalHeader;
		endOfRawData += (fileHeader.NumberOfSections * sizeof(PELIB_IMAGE_SECTION_HEADER));
		if(endOfRawData >= PELIB_PAGE_SIZE)
			return true;

		for(auto & section : sections)
		{
			// Windows's ci!CipImageGetImageHash wants start of any section past SizeOfHeaders
			// TODO: This check doesn't seem to hapeen for 32-bit images. Need confirm/deny this
			// Sample: 0E2EEAC29F7BAD81C67F0283541A050FAED973C114F46CF5F270355623A7BA8A
			if(optionalHeader.Magic == PELIB_IMAGE_NT_OPTIONAL_HDR64_MAGIC)
			{
				if(section.PointerToRawData && section.SizeOfRawData && section.PointerToRawData < optionalHeader.SizeOfHeaders)
				{
					return true;
				}
			}

			if(section.PointerToRawData != 0 && section.PointerToRawData < endOfRawData)
				return true;
			if((section.PointerToRawData + section.SizeOfRawData) < section.PointerToRawData)
				return true;
			if((section.PointerToRawData + section.SizeOfRawData) > peFileSize)
				return true;
			if((section.VirtualAddress + section.SizeOfRawData - 1) < section.SizeOfRawData)
				return true;

			if(section.SizeOfRawData != 0 && (section.PointerToRawData + section.SizeOfRawData) > endOfRawData)
				endOfRawData = (section.PointerToRawData + section.SizeOfRawData);
		}

		// Verify the position and range of the digital signature
		if(SecurityDir.VirtualAddress && SecurityDir.Size)
		{
			if(SecurityDir.VirtualAddress < endOfRawData || SecurityDir.VirtualAddress > peFileSize)
				return true;
			if((SecurityDir.VirtualAddress + SecurityDir.Size) != peFileSize)
				return true;
			if((SecurityDir.VirtualAddress + SecurityDir.Size) < endOfRawData)
				return true;
			if(SecurityDir.VirtualAddress < optionalHeader.SizeOfHeaders)
				return true;
			if(SecurityDir.VirtualAddress & 0x03)
				return true;
		}

		// Windows 8+ fails to load the image if the certificate is zeroed
		// We don't want to parse and verify the certificate here,
		// just check for the most blatantly corrupt certificates
		if(forceIntegrityCheckCertificate)
		{
			std::uint8_t * certPtr = fileData.data() + SecurityDir.VirtualAddress;
			if(SecurityDir.Size > 2 && certPtr[0] == 0 && certPtr[1] == 0)
				return true;
		}
	}

	// All checks passed.
	return false;
}

// Windows 10: For IMAGE_FILE_MACHINE_I386 and IMAGE_FILE_MACHINE_AMD64,
// if(Characteristics & IMAGE_FILE_RELOCS_STRIPPED) and (DllCharacteristics & IMAGE_DLLCHARACTERISTICS_APPCONTAINER),
// MiRelocateImage returns STATUS_INVALID_IMAGE_FORMAT.
bool PeLib::ImageLoader::checkForBadArchitectureSpecific()
{
	// In Windows 10, this check is only performed on "legacy" images
	// (IMAGE_FILE_MACHINE_I386 or IMAGE_FILE_MACHINE_AMD64)
	// Performed by nt!MiRelocateImage -> nt!MiLegacyImageArchitecture
	if(isLegacyImageArchitecture(fileHeader.Machine))
	{
		// If the image has stripped relocations, it can't be an app container
		if((fileHeader.Characteristics & PELIB_IMAGE_FILE_RELOCS_STRIPPED) == 0)
		{
			if(optionalHeader.DllCharacteristics & PELIB_IMAGE_DLLCHARACTERISTICS_APPCONTAINER)
			{
				return true;
			}
		}
	}
	else
	{
		if(checkNonLegacyDllCharacteristics)
		{
			// Check images that do NOT have stripped relocations
			if((fileHeader.Characteristics & PELIB_IMAGE_FILE_RELOCS_STRIPPED) == 0)
			{
				#define MUST_HAVE_FLAGS (PELIB_IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE | PELIB_IMAGE_DLLCHARACTERISTICS_NX_COMPAT)

				if((optionalHeader.DllCharacteristics & MUST_HAVE_FLAGS) != MUST_HAVE_FLAGS)
				{
					return true;
				}
			}
		}
	}

	return false;
}

template <typename LOAD_CONFIG>
bool PeLib::ImageLoader::checkForBadLoadConfigXX(std::uint32_t loadConfigRva, std::uint32_t loadConfigSize)
{
	LOAD_CONFIG LoadConfig = {0};

	// Don't overflow the read
	if(loadConfigSize > sizeof(LOAD_CONFIG))
		loadConfigSize = sizeof(LOAD_CONFIG);

	// Load the load config directory
	if(readImage(&LoadConfig, loadConfigRva, loadConfigSize) == loadConfigSize)
	{
		if(LoadConfig.DynamicValueRelocTableSection >= fileHeader.NumberOfSections)
			return true;

		if(LoadConfig.GuardCFFunctionTable > 0)
		{
			if(LoadConfig.GuardCFFunctionTable < optionalHeader.ImageBase)
				return true;
			if(LoadConfig.GuardCFFunctionCount == 0)
				return true;
		}
	}

	// The load config is OK
	return false;
}

bool PeLib::ImageLoader::checkForImageAfterMapping()
{
	std::uint32_t loadConfigRva = optionalHeader.DataDirectory[PELIB_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
	std::uint32_t loadConfigSize = optionalHeader.DataDirectory[PELIB_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size;

	// Perform the checks of IMAGE_LOAD_CONFIG_DIRECTORY
	// Performed by nt!MiRelocateImage -> nt!MiParseImageLoadConfig, only in case
	// when IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE in IMAGE_OPTIONAL_HEADER::DllCharacteristics is set
	if(optionalHeader.DllCharacteristics & PELIB_IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)
	{
		if(loadConfigRva && loadConfigSize)
		{
			if(optionalHeader.Magic == PELIB_IMAGE_NT_OPTIONAL_HDR32_MAGIC)
			{
				if(checkForBadLoadConfigXX<PELIB_IMAGE_LOAD_CONFIG_DIRECTORY32>(loadConfigRva, loadConfigSize))
					return true;
			}

			if(optionalHeader.Magic == PELIB_IMAGE_NT_OPTIONAL_HDR64_MAGIC)
			{
				if(checkForBadLoadConfigXX<PELIB_IMAGE_LOAD_CONFIG_DIRECTORY64>(loadConfigRva, loadConfigSize))
					return true;
			}
		}
	}

	// Perform extra checks of relocations (performed by nt!MiRelocateImage)
	// Image loading will fail if the architecture is not intel and relocations are screwed
	if(!isLegacyImageArchitecture(fileHeader.Machine))
	{
		PELIB_IMAGE_BASE_RELOCATION BaseReloc;
		std::uint32_t baseRelocRVA = optionalHeader.DataDirectory[PELIB_IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
		std::uint32_t baseRelocSize = optionalHeader.DataDirectory[PELIB_IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

		if(baseRelocRVA && baseRelocSize > sizeof(PELIB_IMAGE_BASE_RELOCATION))
		{
			if(readImage(&BaseReloc, baseRelocRVA, sizeof(PELIB_IMAGE_BASE_RELOCATION)) == sizeof(PELIB_IMAGE_BASE_RELOCATION))
			{
				if(baseRelocSize >= sizeof(PELIB_IMAGE_BASE_RELOCATION) + sizeof(std::uint16_t))
				{
					if(BaseReloc.SizeOfBlock > baseRelocSize)
						return true;
					if(BaseReloc.SizeOfBlock & 0x01)
						return true;
					if(BaseReloc.SizeOfBlock < sizeof(PELIB_IMAGE_BASE_RELOCATION))
						return true;
				}
				else
				{
					if(baseRelocSize != sizeof(PELIB_IMAGE_BASE_RELOCATION))
					{
						return true;
					}
				}

			}
		}
	}

	return false;
}

// Weirdly incorrect check performed by Windows XP's MiCreateImageFileMap.
bool PeLib::ImageLoader::checkForSectionTablesWithinHeader(std::uint32_t e_lfanew)
{
	std::uint32_t OffsetToSectionTable = sizeof(std::uint32_t) + sizeof(PELIB_IMAGE_FILE_HEADER) + fileHeader.SizeOfOptionalHeader;
	std::uint32_t NumberOfSubsections = fileHeader.NumberOfSections;
	std::uint32_t NtHeaderSize;

	// Sample: retdec-regression-tests\features\corkami\inputs\96emptysections.ex
	// Must count with more pages if the header size is greater than one page
	NtHeaderSize = AlignToSize(optionalHeader.SizeOfHeaders, PELIB_PAGE_SIZE) - e_lfanew;

	// If this condition is true, then the image header contains data up to SizeofHeaders
	// If not, the image header contains the entire page.
	if((e_lfanew + OffsetToSectionTable + (NumberOfSubsections + 1) * sizeof(PELIB_IMAGE_SECTION_HEADER)) <= NtHeaderSize)
		return false;

	return true;
}

// Returns true if the image is OK and can be mapped by NtCreateSection(SEC_IMAGE).
// This does NOT mean that the image is executable by CreateProcess - more checks are done,
// like resource integrity or relocation table correctness.
bool PeLib::ImageLoader::isImageLoadable() const
{
	return (ldrError == LDR_ERROR_NONE || ldrError == LDR_ERROR_FILE_IS_CUT_LOADABLE);
}

bool PeLib::ImageLoader::isImageMappedOk() const
{
	// If there was loader error, we didn't map the image
	if(!isImageLoadable())
		return false;
	if(pages.size() == 0)
		return false;
	return true;
}

bool PeLib::ImageLoader::isValidImageBlock(std::uint32_t Rva, std::uint32_t Size) const
{
	if(Rva >= optionalHeader.SizeOfImage || Size >= optionalHeader.SizeOfImage)
		return false;
	if((Rva + Size) < Rva)
		return false;
	if((Rva + Size) > optionalHeader.SizeOfImage)
		return false;
	return true;
}

//-----------------------------------------------------------------------------
// Testing functions

std::size_t PeLib::ImageLoader::getMismatchOffset(
	void * buffer1,
	void * buffer2,
	std::uint32_t rva,
	std::size_t length)
{
	std::uint8_t * byteBuffer1 = reinterpret_cast<std::uint8_t *>(buffer1);
	std::uint8_t * byteBuffer2 = reinterpret_cast<std::uint8_t *>(buffer2);
	std::uint32_t fileOffset = getFileOffsetFromRva(rva);

	for(std::size_t i = 0; i < length; i++)
	{
		if(byteBuffer1[i] != byteBuffer2[i])
		{
			// Windows loader puts 0 in IMAGE_SECTION_HEADER::PointerToRawData if IMAGE_SECTION_HEADER::SizeOfRawData is also zero.
			// However, this is somewhat random - depends on current memory condition, often dissappears
			// when the sample is copied to another location.
			if(isSectionHeaderPointerToRawData(fileOffset + i))
				continue;

			// If under debugger, Microsoft Visual Studio may place a breakpoint
			// at the beginning of __crt_debugger_hook. Ignore such differences
			if(byteBuffer1[i] == 0xCC)
				continue;

			//for(int j = i & 0xFFFFFFF0; j < 0xD00; j++)
			//	printf("byteBuffer1[j]: %02x, byteBuffer2[j]: %02x\n", byteBuffer1[j], byteBuffer2[j]);
			return i;
		}
	}

	return (std::size_t)(-1);
}

void PeLib::ImageLoader::compareWithWindowsMappedImage(
	PELIB_IMAGE_COMPARE & ImageCompare,
	void * imageDataPtr,
	std::uint32_t imageSize)
{
	std::uint8_t * winImageData = reinterpret_cast<std::uint8_t *>(imageDataPtr);
	std::uint8_t * winImageEnd = winImageData + imageSize;
	std::uint8_t singlePage[PELIB_PAGE_SIZE];
	std::size_t mismatchOffset;
	std::size_t rva = 0;

	// Check if the image was loaded by both Windows and us
	// Note that in Windows 7, the image can actually be mapped at base address 0
	// Sample: retdec-regression-tests\features\corkami\inputs\ibnullXP.ex
	if((winImageData || imageSize) && isImageMappedOk())
	{
		// Check whether the image size is the same
		if(imageSize != getSizeOfImageAligned())
		{
			ImageCompare.compareResult = PELIB_COMPARE_RESULT::ImagesDifferentSize;
			ImageCompare.differenceOffset = 0;
			return;
		}

		// Images with extreme value of SizeOfImage take very long time
		// (even hours) to compare under older Windows (7 or older). We skip them
		//if(imageSize & 0xF0000000)
		//{
		//	ImageCompare.compareResult = PELIB_COMPARE_RESULT::ImagesEqual;
		//	ImageCompare.differenceOffset = 0;
		//	return;
		//}

		// Compare images page-by-page
		while(winImageData < winImageEnd)
		{
			// If the windows page is inaccessible, our page must be inaccessible as well
			bool isGoodPageWin = isGoodPagePointer(ImageCompare.PfnVerifyAddress, winImageData);
			bool isGoodPageMy  = isGoodMappedPage(rva);

			// If we have a compare callback, call it
			if(ImageCompare.PfnCompareCallback != nullptr)
			{
				ImageCompare.PfnCompareCallback(&ImageCompare, rva, imageSize);
			}

			// Both are accessible -> Compare the page
			if(isGoodPageWin && isGoodPageMy)
			{
				// Read the image page
				readImage(singlePage, rva, sizeof(singlePage));

				// Windows: Under low memory condition and heavy load, there may be STATUS_IN_PAGE_ERROR
				// exception thrown when touching the mapped image. For that reason,
				// this function must be framed by __try/__except in caller
				if(memcmp(winImageData, singlePage, PELIB_PAGE_SIZE))
				{
					mismatchOffset = getMismatchOffset(winImageData, singlePage, rva, PELIB_PAGE_SIZE);
					if(mismatchOffset != (std::size_t)(-1))
					{
						ImageCompare.compareResult = PELIB_COMPARE_RESULT::ImagesDifferentPageValue;
						ImageCompare.differenceOffset = rva + mismatchOffset;
						return;
					}
				}
			}
			else
			{
				// Accessible vs inacessible?
				if(isGoodPageWin != isGoodPageMy)
				{
					ImageCompare.compareResult = PELIB_COMPARE_RESULT::ImagesDifferentPageAccess;
					ImageCompare.differenceOffset = rva;
					return;
				}
			}

			// Move pointers
			winImageData += PELIB_PAGE_SIZE;
			rva += PELIB_PAGE_SIZE;
		}
	}

	// Check whether both we and Windows mapped the image OK
	if(isImageMappedOk())
	{
		// Windows didn't map the image
		if(winImageData == nullptr)
		{
			ImageCompare.compareResult = PELIB_COMPARE_RESULT::ImagesWindowsDidntLoadWeDid;
			return;
		}
	}
	else
	{
		// Windows mapped the image
		if(winImageData != nullptr)
		{
			ImageCompare.compareResult = PELIB_COMPARE_RESULT::ImagesWindowsLoadedWeDidnt;
			return;
		}
	}

	// Both Windows and our image are the same
	ImageCompare.compareResult = PELIB_COMPARE_RESULT::ImagesEqual;
	ImageCompare.differenceOffset = 0;
}
