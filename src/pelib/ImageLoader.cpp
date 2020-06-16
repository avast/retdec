/*****************************************************************************/
/* ImageLoader.cpp                        Copyright (c) Ladislav Zezula 2020 */
/*---------------------------------------------------------------------------*/
/* Implementation of PE image loader                                         */
/*---------------------------------------------------------------------------*/
/*   Date    Ver   Who  Comment                                              */
/* --------  ----  ---  -------                                              */
/* 30.05.20  1.00  Lad  Created                                              */
/*****************************************************************************/

#include <iostream>
#include <fstream>

#include "ImageLoader.h"

//-----------------------------------------------------------------------------
// Anti-headache

using std::uint8_t;
using std::uint16_t;
using std::uint32_t;
using std::uint64_t;
using std::int16_t;
using std::int32_t;
using std::int64_t;
using std::size_t;

//-----------------------------------------------------------------------------
// Static class variables

uint8_t PeLib::ImageLoader::ImageProtectionArray[16] =
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

PeLib::ImageLoader::ImageLoader(uint32_t loaderFlags)
{
	memset(&dosHeader, 0, sizeof(PELIB_IMAGE_DOS_HEADER));
	memset(&fileHeader, 0, sizeof(PELIB_IMAGE_FILE_HEADER));
	memset(&optionalHeader, 0, sizeof(PELIB_IMAGE_OPTIONAL_HEADER));
	ldrError = LDR_ERROR_NONE;

	// By default, set the most benevolent settings
	sizeofImageMustMatch = false;
	ntHeadersSizeCheck = false;
	appContainerCheck = false;
	maxSectionCount = 255;

	// Resolve os-specific restrictions
	switch(loaderMode = (loaderFlags & WindowsVerMask))
	{
		case LoaderModeWindowsXP:
			maxSectionCount = PE_MAX_SECTION_COUNT_XP;
			sizeofImageMustMatch = true;
			break;

		case LoaderModeWindows7:
			maxSectionCount = PE_MAX_SECTION_COUNT_7;
			ntHeadersSizeCheck = true;
			sizeofImageMustMatch = true;
			break;

		case LoaderModeWindows10:
			maxSectionCount = PE_MAX_SECTION_COUNT_7;
			ntHeadersSizeCheck = true;
			appContainerCheck = true;
			break;
	}
}

PeLib::ImageLoader::~ImageLoader()
{}

//-----------------------------------------------------------------------------
// Public functions

bool PeLib::ImageLoader::relocateImage(uint64_t newImageBase)
{
	uint32_t VirtualAddress;
	uint32_t Size;
	bool result = true;

	// Only relocate the image if the image base is different
	if(newImageBase != optionalHeader.ImageBase)
	{
		// If relocations are stripped, there is no relocation
		if(fileHeader.Characteristics & PELIB_IMAGE_FILE_RELOCS_STRIPPED)
			return false;

		// Windows 10 (built 10240) performs this check
		if(appContainerCheck && checkForBadAppContainer())
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

		// Resolve case when the reloc block is too big
		if((VirtualAddress + Size) > getSizeOfImage())
			Size = getSizeOfImage() - VirtualAddress;

		// Perform relocations
		result = processImageRelocations(optionalHeader.ImageBase, newImageBase, VirtualAddress, Size);
	}

	return result;
}

uint32_t PeLib::ImageLoader::readImage(void * buffer, uint32_t rva, uint32_t bytesToRead)
{
	return readWriteImage(buffer, rva, bytesToRead, readFromPage);
}

uint32_t PeLib::ImageLoader::writeImage(void * buffer, std::uint32_t rva, std::uint32_t bytesToRead)
{
	return readWriteImage(buffer, rva, bytesToRead, writeToPage);
}

uint32_t PeLib::ImageLoader::dumpImage(const char * fileName)
{
	// Create the file for dumping
	std::ofstream fs(fileName, std::ofstream::binary);
	uint32_t bytesWritten = 0;

	if(fs.is_open())
	{
		// Allocate one page filled with zeros
		uint8_t zeroPage[PELIB_PAGE_SIZE] = {0};
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

uint64_t PeLib::ImageLoader::getImageBase()
{
	return optionalHeader.ImageBase;
}

uint32_t PeLib::ImageLoader::getSizeOfImage()
{
	return optionalHeader.SizeOfImage;
}

uint32_t PeLib::ImageLoader::getSizeOfImageAligned()
{
	return AlignToSize(optionalHeader.SizeOfImage, PELIB_PAGE_SIZE);
}

uint32_t PeLib::ImageLoader::getFileOffsetFromRva(std::uint32_t rva)
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
				uint32_t sectionRvaStart = sectHdr.VirtualAddress;
				uint32_t virtualSize = (sectHdr.VirtualSize != 0) ? sectHdr.VirtualSize : sectHdr.SizeOfRawData;

				if(sectionRvaStart <= rva && rva < (sectionRvaStart + virtualSize))
				{
					// Make sure we round the pointer to raw data down to PELIB_SECTOR_SIZE.
					// In case when PointerToRawData is less than 0x200, it maps to the header!
					return sectHdr.PointerToRawData & ~(PELIB_SECTOR_SIZE - 1);
				}
			}
		}

		// Check if the rva goes into the header
		return (rva < optionalHeader.SizeOfHeaders) ? rva : UINT32_MAX;
	}

	// The rva maps directly to the fille offset
	return rva;
}

uint32_t PeLib::ImageLoader::getImageProtection(std::uint32_t sectionCharacteristics)
{
	uint32_t Index = 0;

	if (sectionCharacteristics & PELIB_IMAGE_SCN_MEM_EXECUTE)
		Index |= 1;

	if (sectionCharacteristics & PELIB_IMAGE_SCN_MEM_READ)
		Index |= 2;

	if (sectionCharacteristics & PELIB_IMAGE_SCN_MEM_WRITE)
		Index |= 4;

	if (sectionCharacteristics & PELIB_IMAGE_SCN_MEM_SHARED)
		Index |= 8;

	return ImageProtectionArray[Index];
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

PeLib::LoaderError PeLib::ImageLoader::loaderError()
{
	return ldrError;
}

//-----------------------------------------------------------------------------
// Interface for loading files

int PeLib::ImageLoader::Load(std::vector<uint8_t> & fileData, bool loadHeadersOnly)
{
	int fileError;
	
	// Check and capture DOS header
	fileError = captureDosHeader(fileData);
	if(fileError != ERROR_NONE)
		return fileError;

	// Check and capture NT headers
	fileError = captureNtHeaders(fileData);
	if(fileError != ERROR_NONE)
		return fileError;

	// Check and capture section headers
	fileError = captureSectionHeaders(fileData);
	if(fileError != ERROR_NONE)
		return fileError;

	// Shall we map the image content?
	if(loadHeadersOnly == false)
	{
		// If there was no detected image error, map the image as if Windows loader would do
		if(ldrError == LDR_ERROR_NONE || ldrError == LDR_ERROR_FILE_IS_CUT_LOADABLE)
		{
			fileError = captureImageSections(fileData);
		}

		// If there was any kind of error that prevents the image from being mapped,
		// we load the content as-is and translate virtual addresses using getFileOffsetFromRva
		if(pages.size() == 0)
		{
			fileError = loadImageAsIs(fileData);
		}
	}

	return fileError;
}

int PeLib::ImageLoader::Load(std::ifstream & fs, std::streamoff fileOffset, bool loadHeadersOnly)
{
	std::vector<uint8_t> fileData;
	std::streampos fileSize;
	size_t fileSize2;

	// Get the file size and move to the desired offset
	fs.seekg(0, std::ios::end);
	fileSize = fs.tellg();
	fs.seekg(fileOffset);

	// The file must be greater than sizeof DOS header
	if(fileSize < sizeof(PELIB_IMAGE_DOS_HEADER))
		return ERROR_INVALID_FILE;
	
	// Windows loader refuses to load any file which is larger than 0xFFFFFFFF
	if((fileSize >> 32) != 0)
		return setLoaderError(LDR_ERROR_FILE_TOO_BIG);
	fileSize2 = static_cast<size_t>(fileSize);

	// Resize the vector so it can hold entire file
	fileData.resize(fileSize2);

	// Read the entire file to memory
	if(fs.read(reinterpret_cast<char*>(fileData.data()), fileSize2).bad())
		return false;

	// Call the Load interface on char buffer
	return Load(fileData, loadHeadersOnly);
}

int PeLib::ImageLoader::Load(const char * fileName, bool loadHeadersOnly)
{
	std::ifstream fs(fileName, std::ifstream::in | std::ifstream::binary);
	if(!fs.is_open())
		return ERROR_OPENING_FILE;

	return Load(fs, loadHeadersOnly);
}

//-----------------------------------------------------------------------------
// Protected functions

void PeLib::ImageLoader::readFromPage(PELIB_FILE_PAGE & page, void * buffer, size_t offsetInPage, size_t bytesInPage)
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

void PeLib::ImageLoader::writeToPage(PELIB_FILE_PAGE & page, void * buffer, size_t offsetInPage, size_t bytesInPage)
{
	// Write the data to the page
	page.writeToPage(buffer, offsetInPage, bytesInPage);
}

uint32_t PeLib::ImageLoader::readWriteImage(void * buffer, uint32_t rva, uint32_t bytesToRead, READWRITE ReadWrite)
{
	uint32_t bytesRead = 0;
	uint32_t rvaEnd = rva + bytesToRead;

	// Check the last possible address where we read
	if(rvaEnd > getSizeOfImageAligned())
		rvaEnd = getSizeOfImageAligned();

	// Is the offset within the image?
	if(rva < rvaEnd)
	{
		uint8_t * bufferPtr = static_cast<uint8_t *>(buffer);
		size_t pageIndex = rva / PELIB_PAGE_SIZE;

		// The page index must be in range
		if(pageIndex < pages.size())
		{
			while(rva < rvaEnd)
			{
				PELIB_FILE_PAGE & page = pages[pageIndex++];
				uint32_t offsetInPage = rva & (PELIB_PAGE_SIZE - 1);
				uint32_t bytesInPage = PELIB_PAGE_SIZE - offsetInPage;

				// Perhaps the last page loaded?
				if(bytesInPage > (rvaEnd - rva))
					bytesInPage = (rvaEnd - rva);

				// Perform the read/write operation
				ReadWrite(page, bufferPtr, offsetInPage, bytesInPage);

				// Move pointers
				bufferPtr += bytesInPage;
				bytesRead += bytesInPage;
				rva += bytesInPage;
			}
		}
	}

	// Return the number of bytes that were read
	return bytesRead;
}

bool PeLib::ImageLoader::processImageRelocations(uint64_t oldImageBase, uint64_t newImageBase, uint32_t VirtualAddress, uint32_t Size)
{
	uint64_t difference = (newImageBase - oldImageBase);
	uint8_t * bufferEnd;
	uint8_t * bufferPtr;
	uint8_t * buffer;

	// No not accept anything less than size of relocation block
	if(Size < sizeof(PELIB_IMAGE_BASE_RELOCATION))
		return false;

	// Allocate and read the relocation block
	bufferPtr = buffer = new uint8_t[Size];
	if(buffer != nullptr)
	{
		// Read the relocations from the file
		bufferEnd = buffer + readImage(buffer, VirtualAddress, Size);

		// Keep going while there is relocation blocks
		while((bufferPtr + sizeof(PELIB_IMAGE_BASE_RELOCATION)) <= bufferEnd)
		{
			PELIB_IMAGE_BASE_RELOCATION * pRelocBlock = (PELIB_IMAGE_BASE_RELOCATION *)(bufferPtr);
			uint16_t * typeAndOffset = (uint16_t * )(pRelocBlock + 1);
			uint32_t numRelocations;

			// Skip relocation blocks which have invalid size in the header
			if(pRelocBlock->SizeOfBlock <= sizeof(PELIB_IMAGE_BASE_RELOCATION))
			{
				bufferPtr += sizeof(PELIB_IMAGE_BASE_RELOCATION);
				continue;
			}

			// Windows loader seems to skip relocation blocks that go into a zero page
			// Sample: e380e6968f1b431e245f811f94cef6a5b6e17fd7c90ef283338fa1959eb3c536
			if(isZeroPage(pRelocBlock->VirtualAddress))
			{
				bufferPtr += pRelocBlock->SizeOfBlock;
				continue;
			}

			// Calculate number of relocation entries. Prevent buffer overflow
			if((bufferPtr + pRelocBlock->SizeOfBlock) > bufferEnd)
				pRelocBlock->SizeOfBlock = bufferEnd - bufferPtr;
			numRelocations = (pRelocBlock->SizeOfBlock - sizeof(PELIB_IMAGE_BASE_RELOCATION)) / sizeof(uint16_t);

			// Parse relocations
			for(uint32_t i = 0; i < numRelocations; i++)
			{
				uint32_t fixupAddress = pRelocBlock->VirtualAddress + (typeAndOffset[i] & 0x0FFF);
				int32_t temp;

				switch(typeAndOffset[i] >> 12)
				{
					case PELIB_IMAGE_REL_BASED_DIR64:         // The base relocation applies the difference to the 64-bit field at offset.
					{
						int64_t fixupValue = 0;

						if(readImage(&fixupValue, fixupAddress, sizeof(fixupValue)) != sizeof(fixupValue))
							break;
						fixupValue += difference;
						writeImage(&fixupValue, fixupAddress, sizeof(fixupValue));
						break;
					}

					case PELIB_IMAGE_REL_BASED_HIGHLOW:       // The base relocation applies all 32 bits of the difference to the 32-bit field at offset.
					{
						int32_t fixupValue = 0;

						if(readImage(&fixupValue, fixupAddress, sizeof(fixupValue)) != sizeof(fixupValue))
							break;
						fixupValue += (int32_t)difference;
						writeImage(&fixupValue, fixupAddress, sizeof(fixupValue));
						break;
					}

					case PELIB_IMAGE_REL_BASED_HIGH:          // The base relocation adds the high 16 bits of the difference to the 16-bit field at offset.
					{
						int16_t fixupValue = 0;

						if(readImage(&fixupValue, fixupAddress, sizeof(fixupValue)) != sizeof(fixupValue))
							break;
						temp = (fixupValue << 16);
						temp += (int32_t)difference;
						fixupValue = (int16_t)(temp >> 16);
						writeImage(&fixupValue, fixupAddress, sizeof(fixupValue));
						break;
					}

					case PELIB_IMAGE_REL_BASED_HIGHADJ:       // The base relocation adds the high 16 bits of the difference to the 16-bit field at offset.
					{
						int16_t fixupValue = 0;

						if(readImage(&fixupValue, fixupAddress, sizeof(fixupValue)) != sizeof(fixupValue))
							break;
						temp = (fixupValue << 16);
						temp += (int32_t)typeAndOffset[++i];
						temp += (int32_t)difference;
						temp += 0x8000;
						fixupValue = (int16_t)(temp >> 16);
						writeImage(&fixupValue, fixupAddress, sizeof(fixupValue));
						break;
					}

					case PELIB_IMAGE_REL_BASED_LOW:           // The base relocation adds the low 16 bits of the difference to the 16-bit field at offset.
					{
						int16_t fixupValue = 0;

						if(readImage(&fixupValue, fixupAddress, sizeof(fixupValue)) != sizeof(fixupValue))
							break;
						fixupValue = (int16_t)((int32_t)fixupValue + difference);
						writeImage(&fixupValue, fixupAddress, sizeof(fixupValue));
						break;
					}

					case PELIB_IMAGE_REL_BASED_MIPS_JMPADDR:  // Relocate a MIPS jump address. 
					{
						uint32_t fixupValue = 0;

						if(readImage(&fixupValue, fixupAddress, sizeof(fixupValue)) != sizeof(fixupValue))
							break;
						temp = (fixupValue & 0x3ffffff) << 2;
						temp += (int32_t)difference;
						fixupValue = (fixupValue & ~0x3ffffff) | ((temp >> 2) & 0x3ffffff);
						writeImage(&fixupValue, fixupAddress, sizeof(fixupValue));
						break;
					}

					case PELIB_IMAGE_REL_BASED_ABSOLUTE:      // Absolute - no fixup required. 
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
	uint32_t offset = dosHeader.e_lfanew + sizeof(uint32_t) + sizeof(PELIB_IMAGE_FILE_HEADER);

	// 64-bit images
	if(optionalHeader.Magic == PELIB_IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		PELIB_IMAGE_OPTIONAL_HEADER64 header64{};

		readImage(&header64, offset, fileHeader.SizeOfOptionalHeader);
		header64.ImageBase = newImageBase;
		writeImage(&header64, offset, fileHeader.SizeOfOptionalHeader);
	}

	// 32-bit images
	if(optionalHeader.Magic == PELIB_IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	{
		PELIB_IMAGE_OPTIONAL_HEADER32 header32{};

		readImage(&header32, offset, fileHeader.SizeOfOptionalHeader);
		header32.ImageBase = (uint32_t)newImageBase;
		writeImage(&header32, offset, fileHeader.SizeOfOptionalHeader);
	}
}

int PeLib::ImageLoader::captureDosHeader(std::vector<uint8_t> & fileData)
{
	uint8_t * fileBegin = fileData.data();
	uint8_t * fileEnd = fileBegin + fileData.size();

	// Capture the DOS header
	if((fileBegin + sizeof(PELIB_IMAGE_DOS_HEADER)) >= fileEnd)
		return ERROR_INVALID_FILE;
	memcpy(&dosHeader, fileBegin, sizeof(PELIB_IMAGE_DOS_HEADER));

	// Verify DOS header
	if(dosHeader.e_magic != PELIB_IMAGE_DOS_SIGNATURE)
		return ERROR_INVALID_FILE;
	if(dosHeader.e_lfanew & 3)
		return setLoaderError(LDR_ERROR_E_LFANEW_UNALIGNED);
	if(dosHeader.e_lfanew > fileData.size())
		return setLoaderError(LDR_ERROR_E_LFANEW_OUT_OF_FILE);

	return ERROR_NONE;
}

int PeLib::ImageLoader::captureNtHeaders(std::vector<uint8_t> & fileData)
{
	uint8_t * fileBegin = fileData.data();
	uint8_t * filePtr = fileBegin + dosHeader.e_lfanew;
	uint8_t * fileEnd = fileBegin + fileData.size();
	uint32_t ntSignature;
	size_t ntHeaderSize;

	// Windows 7 or newer require that the file size is greater or equal to sizeof(IMAGE_NT_HEADERS)
	// Note that 64-bit kernel requires this to be sizeof(IMAGE_NT_HEADERS64)
	if(ntHeadersSizeCheck)
	{
		uint32_t minFileSize = dosHeader.e_lfanew + sizeof(uint32_t) + sizeof(PELIB_IMAGE_FILE_HEADER) + sizeof(PELIB_IMAGE_OPTIONAL_HEADER32);

		if((filePtr + minFileSize) > fileEnd)
			return setLoaderError(LDR_ERROR_NTHEADER_OUT_OF_FILE);
	}

	// Capture the NT signature
	if((filePtr + sizeof(uint32_t)) >= fileEnd)
		setLoaderError(LDR_ERROR_NTHEADER_OUT_OF_FILE);
	ntSignature = *(reinterpret_cast<uint32_t *>(filePtr));

	// Check the NT signature
	if(ntSignature != PELIB_IMAGE_NT_SIGNATURE)
		setLoaderError(LDR_ERROR_NO_NT_SIGNATURE);
	filePtr += sizeof(uint32_t);

	// Capture the file header
	if((filePtr + sizeof(PELIB_IMAGE_FILE_HEADER)) >= fileEnd)
		setLoaderError(LDR_ERROR_NTHEADER_OUT_OF_FILE);
	memcpy(&fileHeader, filePtr, sizeof(PELIB_IMAGE_FILE_HEADER));

	// 7baebc6d9f2185fafa760c875ab1386f385a0b3fecf2e6ae339abb4d9ac58f3e
	if (fileHeader.Machine == 0 && fileHeader.SizeOfOptionalHeader == 0)
		setLoaderError(LDR_ERROR_FILE_HEADER_INVALID);
	if (!(fileHeader.Characteristics & PELIB_IMAGE_FILE_EXECUTABLE_IMAGE))
		setLoaderError(LDR_ERROR_IMAGE_NON_EXECUTABLE);
	filePtr += sizeof(PELIB_IMAGE_FILE_HEADER);

	// Windows XP: Number of section must be 96
	// Windows 7: Number of section must be 192
	if(fileHeader.NumberOfSections > maxSectionCount)
		setLoaderError(LDR_ERROR_IMAGE_NON_EXECUTABLE);

	// Check the position of the NT header for integer overflow and for file size overflow
	ntHeaderSize = sizeof(uint32_t) + sizeof(PELIB_IMAGE_FILE_HEADER) + fileHeader.SizeOfOptionalHeader;
	if((dosHeader.e_lfanew + ntHeaderSize) < dosHeader.e_lfanew)
		setLoaderError(LDR_ERROR_NTHEADER_OFFSET_OVERFLOW);

	// Capture optional header
	if(fileHeader.Machine == PELIB_IMAGE_FILE_MACHINE_I386)
		captureOptionalHeader32(filePtr, fileEnd);
	else
		captureOptionalHeader64(filePtr, fileEnd);

	// Performed by Windows 10 (nt!MiVerifyImageHeader):
	// Sample: 04d3577d1b6309a0032d4c4c1252c55416a09bb617aebafe512fffbdd4f08f18
	if(appContainerCheck && checkForBadAppContainer())
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
	if (optionalHeader.SectionAlignment == 0)
		setLoaderError(LDR_ERROR_SECTION_ALIGNMENT_ZERO);

	// Section alignment must be a power of 2
	if (optionalHeader.SectionAlignment & (optionalHeader.SectionAlignment - 1))
		setLoaderError(LDR_ERROR_SECTION_ALIGNMENT_NOT_POW2);

	if (optionalHeader.SectionAlignment < optionalHeader.FileAlignment)
		setLoaderError(LDR_ERROR_SECTION_ALIGNMENT_TOO_SMALL);

	// Check for images with "super-section": FileAlignment must be equal to SectionAlignment
	if ((optionalHeader.FileAlignment & 511) && (optionalHeader.SectionAlignment != optionalHeader.FileAlignment))
		setLoaderError(LDR_ERROR_SECTION_ALIGNMENT_INVALID);

	// Check for largest image
	if(optionalHeader.SizeOfImage > PELIB_MM_SIZE_OF_LARGEST_IMAGE)
		setLoaderError(LDR_ERROR_SIZE_OF_IMAGE_TOO_BIG);

	// Check for 32-bit images
	if (optionalHeader.Magic == PELIB_IMAGE_NT_OPTIONAL_HDR32_MAGIC && fileHeader.Machine != PELIB_IMAGE_FILE_MACHINE_I386)
		setLoaderError(LDR_ERROR_INVALID_MACHINE32);

	// Check for 64-bit images
	if (optionalHeader.Magic == PELIB_IMAGE_NT_OPTIONAL_HDR64_MAGIC)
	{
		if (fileHeader.Machine != PELIB_IMAGE_FILE_MACHINE_AMD64 && fileHeader.Machine != PELIB_IMAGE_FILE_MACHINE_IA64)
			setLoaderError(LDR_ERROR_INVALID_MACHINE64);
	}

	// Check the size of image
	if(optionalHeader.SizeOfHeaders > optionalHeader.SizeOfImage)
		setLoaderError(LDR_ERROR_SIZE_OF_HEADERS_INVALID);

	// On 64-bit Windows, size of optional header must be properly aligned to 8-byte boundary
	if (fileHeader.SizeOfOptionalHeader & (sizeof(uint64_t) - 1))
		setLoaderError(LDR_ERROR_SIZE_OF_OPTHDR_NOT_ALIGNED);

	// Set the size of image
	if(BytesToPages(optionalHeader.SizeOfImage) == 0)
		setLoaderError(LDR_ERROR_SIZE_OF_IMAGE_ZERO);

	// Check for proper alignment of the image base
	if(optionalHeader.ImageBase & (PELIB_SIZE_64KB - 1))
		setLoaderError(LDR_ERROR_IMAGE_BASE_NOT_ALIGNED);

	return ERROR_NONE;
}

int PeLib::ImageLoader::captureSectionHeaders(std::vector<uint8_t> & fileData)
{
	uint8_t * fileBegin = fileData.data();
	uint8_t * filePtr;
	uint8_t * fileEnd = fileBegin + fileData.size();
	bool bRawDataBeyondEOF = false;

	// Check whether the sections are within the file
	filePtr = fileBegin + dosHeader.e_lfanew + sizeof(uint32_t) + sizeof(PELIB_IMAGE_FILE_HEADER) + fileHeader.SizeOfOptionalHeader;
	if(filePtr > fileEnd)
		return setLoaderError(LDR_ERROR_SECTION_HEADERS_OUT_OF_IMAGE);

	// Set the counters
	uint32_t NumberOfSectionPTEs = AlignToSize(optionalHeader.SizeOfHeaders, optionalHeader.SectionAlignment) / PELIB_PAGE_SIZE;
	uint64_t NextVirtualAddress = 0;
	uint32_t NumberOfPTEs = BytesToPages(optionalHeader.SizeOfImage);
	uint32_t FileAlignmentMask = optionalHeader.FileAlignment - 1;
	bool SingleSubsection = (optionalHeader.SectionAlignment < PELIB_PAGE_SIZE);

	// Verify the image
	if (!SingleSubsection)
	{
		// Some extra checks done by the loader
		if ((optionalHeader.SizeOfHeaders + (optionalHeader.SectionAlignment - 1)) < optionalHeader.SizeOfHeaders)
			setLoaderError(LDR_ERROR_SECTION_HEADERS_OVERFLOW);

		if (NumberOfSectionPTEs > NumberOfPTEs)
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
	for(uint16_t i = 0; i < fileHeader.NumberOfSections; i++)
	{
		PELIB_IMAGE_SECTION_HEADER sectHdr{};

		// Capture one section header
		if((filePtr + sizeof(PELIB_IMAGE_SECTION_HEADER)) > fileEnd)
			break;
		memcpy(&sectHdr, filePtr, sizeof(PELIB_IMAGE_SECTION_HEADER));

		uint32_t PointerToRawData = (sectHdr.SizeOfRawData != 0) ? sectHdr.PointerToRawData : 0;
		uint32_t EndOfRawData = PointerToRawData + sectHdr.SizeOfRawData;
		uint32_t VirtualSize = (sectHdr.VirtualSize != 0) ? sectHdr.VirtualSize : sectHdr.SizeOfRawData;

		// Overflow check
		if ((PointerToRawData + sectHdr.SizeOfRawData) < PointerToRawData)
			setLoaderError(LDR_ERROR_RAW_DATA_OVERFLOW);

		// Verify the image
		if (SingleSubsection)
		{
			// If the image is mapped as single subsection,
			// then the virtual values must match raw values
			if ((sectHdr.VirtualAddress != PointerToRawData) || sectHdr.SizeOfRawData < VirtualSize)
				setLoaderError(LDR_ERROR_SECTION_SIZE_MISMATCH);
		}
		else
		{
			// Check the virtual address of the section
			if (NextVirtualAddress != sectHdr.VirtualAddress)
				setLoaderError(LDR_ERROR_INVALID_SECTION_VA);

			// Check the end of the section
			if((NextVirtualAddress + VirtualSize) <= NextVirtualAddress)
				setLoaderError(LDR_ERROR_INVALID_SECTION_VSIZE);

			// Check section size
			if ((VirtualSize + (PELIB_PAGE_SIZE - 1)) <= VirtualSize)
				setLoaderError(LDR_ERROR_INVALID_SECTION_VSIZE);

			// Calculate number of PTEs in the section
			NumberOfSectionPTEs = AlignToSize(VirtualSize, optionalHeader.SectionAlignment) / PELIB_PAGE_SIZE;
			if (NumberOfSectionPTEs > NumberOfPTEs)
				setLoaderError(LDR_ERROR_INVALID_SECTION_VSIZE);

			NumberOfPTEs -= NumberOfSectionPTEs;

			// Check end of the raw data for the section
			if (((PointerToRawData + sectHdr.SizeOfRawData + FileAlignmentMask) & ~FileAlignmentMask) < PointerToRawData)
				setLoaderError(LDR_ERROR_INVALID_SECTION_RAWSIZE);

			// On last section, size of raw data must not go after the end of the file
			// Sample: a5957dad4b3a53a5894708c7c1ba91be0668ecbed49e33affee3a18c0737c3a5
			if(i == fileHeader.NumberOfSections - 1 && sectHdr.SizeOfRawData != 0)
			{
				if((sectHdr.PointerToRawData + sectHdr.SizeOfRawData) > fileData.size())
					setLoaderError(LDR_ERROR_INVALID_SECTION_RAWSIZE);
			}

			NextVirtualAddress += NumberOfSectionPTEs * PELIB_PAGE_SIZE;
		}

		// Check for raw data beyond end-of-file
		// Note that Windows loader doesn't check this on files that are mapped as single section.
		// We will do that nontheless, because we want to know that a file is cut.
		if (PointerToRawData != 0 && (fileBegin + EndOfRawData) > fileEnd)
			bRawDataBeyondEOF = true;

		// Insert the header to the list
		sections.push_back(sectHdr);
		filePtr += sizeof(PELIB_IMAGE_SECTION_HEADER);
	}

	// Verify the image size. Note that this check is no longer performed by Windows 10
	if(sizeofImageMustMatch)
	{
		uint32_t ThresholdNumberOfPTEs = (SingleSubsection == false) ? (optionalHeader.SectionAlignment / PELIB_PAGE_SIZE) : 1;
		if (NumberOfPTEs >= ThresholdNumberOfPTEs)
		{
			setLoaderError(LDR_ERROR_INVALID_SIZE_OF_IMAGE);
		}
	}

	// Did we detect a trimmed file?
	if (bRawDataBeyondEOF)
	{
		bool bFileLoadable = false;

		// Special exception: Even if cut, the file is still loadable
		// if the last section is in the file range. This is because
		// the PE loader in Windows only cares about whether the last section is in the file range
		if(SingleSubsection == false)
		{
			if (!sections.empty())
			{
				PELIB_IMAGE_SECTION_HEADER & lastSection = sections.back();
				uint32_t PointerToRawData = (lastSection.SizeOfRawData != 0) ? lastSection.PointerToRawData : 0;
				uint32_t EndOfRawData = PointerToRawData + lastSection.SizeOfRawData;

				if ((lastSection.SizeOfRawData == 0) || (fileBegin + EndOfRawData) <= fileEnd)
				{
					setLoaderError(LDR_ERROR_FILE_IS_CUT_LOADABLE);
					bFileLoadable = true;
				}
			}
		}
		else
		{
			setLoaderError(LDR_ERROR_FILE_IS_CUT_LOADABLE);
			bFileLoadable = true;
		}

		// If the file is not loadable, set the "file is cut" error
		if (bFileLoadable == false)
		{
			setLoaderError(LDR_ERROR_FILE_IS_CUT);
		}
	}

	return ERROR_NONE;
}

int PeLib::ImageLoader::captureImageSections(std::vector<uint8_t> & fileData)
{
	uint32_t virtualAddress = 0;
	uint32_t sizeOfImage;

	// Reserve the image size, aligned up to the page size
	sizeOfImage = AlignToSize(optionalHeader.SizeOfImage, PELIB_PAGE_SIZE);
	pages.resize(sizeOfImage / PELIB_PAGE_SIZE);

	// Section-based mapping / file-based mapping
	if(optionalHeader.SectionAlignment >= PELIB_PAGE_SIZE)
	{
		// Capture the file header
		virtualAddress = captureImageSection(fileData, virtualAddress, optionalHeader.SizeOfHeaders, 0, optionalHeader.SizeOfHeaders, PELIB_IMAGE_SCN_MEM_READ, true);
		if(virtualAddress == 0)
			return ERROR_INVALID_FILE;

		// Capture each section
		if(sections.size() != 0)
		{
			for(auto & sectionHeader : sections)
			{
				// Capture all pages from the section
				if(captureImageSection(fileData, sectionHeader.VirtualAddress,
												 sectionHeader.VirtualSize,
												 sectionHeader.PointerToRawData,
												 sectionHeader.SizeOfRawData,
												 sectionHeader.Characteristics) == 0)
				{
					setLoaderError(LDR_ERROR_INVALID_SECTION_VA);
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
		// Capture the file as-is
		virtualAddress = captureImageSection(fileData, 0, sizeOfImage, 0, sizeOfImage, PELIB_IMAGE_SCN_MEM_WRITE | PELIB_IMAGE_SCN_MEM_READ | PELIB_IMAGE_SCN_MEM_EXECUTE, true);
		if(virtualAddress == 0)
			return ERROR_INVALID_FILE;
	}

	// If a section has SizeOfRawData equal to 0,
	// Windows loader patches PointerToRawData to zero, including the mapped image.
	// Tested on Windows XP and Windows 10.
	uint32_t rva = dosHeader.e_lfanew + sizeof(uint32_t) + sizeof(PELIB_IMAGE_FILE_HEADER) + fileHeader.SizeOfOptionalHeader;
	for(size_t i = 0; i < sections.size(); i++, rva += sizeof(PELIB_IMAGE_SECTION_HEADER))
	{
		PELIB_IMAGE_SECTION_HEADER sectHdr{};

		// Read the section from the header. This is necessary, as for some files,
		// section headers are not contained in the image.
		// Example: c8b31a912d91407a834071268366eb404d5e771b8281fdde301e15a8a82bf01b
		readImage(&sectHdr, rva, sizeof(PELIB_IMAGE_SECTION_HEADER));

		// Patch PointerToRawData to zero, if SizeOfRawData is zero.
		if(sectHdr.PointerToRawData != 0 && sectHdr.SizeOfRawData == 0)
		{
			sectHdr.PointerToRawData = 0;
			writeImage(&sectHdr, rva, sizeof(PELIB_IMAGE_SECTION_HEADER));
		}
	}

	return ERROR_NONE;
}

int PeLib::ImageLoader::captureOptionalHeader32(uint8_t * filePtr, uint8_t * fileEnd)
{
	PELIB_IMAGE_OPTIONAL_HEADER32 optionalHeader32{};
	uint32_t sizeOfOptionalHeader = fileHeader.SizeOfOptionalHeader;
	uint32_t numberOfRvaAndSizes;

	// Capture optional header
	if((filePtr + sizeOfOptionalHeader) > fileEnd)
		return setLoaderError(LDR_ERROR_NTHEADER_OUT_OF_FILE);
	if(sizeOfOptionalHeader > sizeof(PELIB_IMAGE_OPTIONAL_HEADER32))
		sizeOfOptionalHeader = sizeof(PELIB_IMAGE_OPTIONAL_HEADER32);
	memcpy(&optionalHeader32, filePtr, sizeOfOptionalHeader);

	// Verify whether it's 32-bit optional header
	if(optionalHeader32.Magic != PELIB_IMAGE_NT_OPTIONAL_HDR32_MAGIC)
	   return setLoaderError(LDR_ERROR_NO_OPTHDR_MAGIC);

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
	if((numberOfRvaAndSizes = optionalHeader32.NumberOfRvaAndSizes) > PELIB_IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
		numberOfRvaAndSizes = PELIB_IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
	memcpy(optionalHeader.DataDirectory, optionalHeader32.DataDirectory, sizeof(PELIB_IMAGE_DATA_DIRECTORY) * numberOfRvaAndSizes);

	return ERROR_NONE;
}

int PeLib::ImageLoader::loadImageAsIs(std::vector<std::uint8_t> & fileData)
{
	imageAsIs = fileData;
	return ERROR_NONE;
}

int PeLib::ImageLoader::captureOptionalHeader64(uint8_t * filePtr, uint8_t * fileEnd)
{
	PELIB_IMAGE_OPTIONAL_HEADER64 optionalHeader64{};
	uint32_t sizeOfOptionalHeader = fileHeader.SizeOfOptionalHeader;
	uint32_t numberOfRvaAndSizes;

	// Capture optional header
	if((filePtr + sizeOfOptionalHeader) > fileEnd)
		return setLoaderError(LDR_ERROR_NTHEADER_OUT_OF_FILE);
	if(sizeOfOptionalHeader > sizeof(PELIB_IMAGE_OPTIONAL_HEADER64))
		sizeOfOptionalHeader = sizeof(PELIB_IMAGE_OPTIONAL_HEADER64);
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
	if((numberOfRvaAndSizes = optionalHeader64.NumberOfRvaAndSizes) > PELIB_IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
		numberOfRvaAndSizes = PELIB_IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
	memcpy(optionalHeader.DataDirectory, optionalHeader64.DataDirectory, sizeof(PELIB_IMAGE_DATA_DIRECTORY) * numberOfRvaAndSizes);

	return ERROR_NONE;
}

size_t PeLib::ImageLoader::getMismatchOffset(void * buffer1, void * buffer2, uint32_t rva, size_t length)
{
	uint8_t * byteBuffer1 = reinterpret_cast<uint8_t *>(buffer1);
	uint8_t * byteBuffer2 = reinterpret_cast<uint8_t *>(buffer2);

	for(size_t i = 0; i < length; i++)
	{
		if(byteBuffer1[i] != byteBuffer2[i])
		{
			// Windows loader puts 0 in IMAGE_SECTION_HEADER::PointerToRawData
			// if IMAGE_SECTION_HEADER::SizeOfRawData is also zero. 
			// However, on random samples, there seems to be the original value.
			// This seems to happen randomly on some samples, often dissappears
			// when the sample is copied to another location.
			if(isRvaOfSectionHeaderPointerToRawData(rva + i))
				continue;

			//for(int j = i & 0xFFFFFFF0; j < 0xD00; j++)
			//	printf("byteBuffer1[j]: %02x, byteBuffer2[j]: %02x\n", byteBuffer1[j], byteBuffer2[j]);
			return i;
		}
	}

	return (size_t)(-1);
}

uint32_t PeLib::ImageLoader::captureImageSection(
	std::vector<uint8_t> & fileData,
	uint32_t virtualAddress,
	uint32_t virtualSize,
	uint32_t pointerToRawData,
	uint32_t sizeOfRawData,
	uint32_t characteristics,
	bool isImageHeader)
{
	uint8_t * fileBegin = fileData.data();
	uint8_t * rawDataPtr;
	uint8_t * rawDataEnd;
	uint8_t * fileEnd = fileBegin + fileData.size();
	uint32_t sizeOfInitializedPages;            // The part of section with initialized pages
	uint32_t sizeOfValidPages;                  // The part of section with valid pages
	uint32_t sizeOfSection;                     // Total virtual size of the section
	uint32_t pageOffset = 0;
	size_t pageIndex;

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
	sizeOfSection = AlignToSize(virtualSize, optionalHeader.SectionAlignment);

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
			while(pageOffset < sizeOfInitializedPages)
			{
				PELIB_FILE_PAGE & filePage = pages[pageIndex++];

				// Only if we didn't get out of the file
				if(rawDataPtr < fileEnd)
				{
					size_t bytesToCopy = PELIB_PAGE_SIZE;

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
		while(pageOffset < sizeOfValidPages)
		{
			PELIB_FILE_PAGE & filePage = pages[pageIndex++];

			filePage.setZeroPage();
			pageOffset += PELIB_PAGE_SIZE;
		}
	}

	// Leave all other pages filled with zeros
	return virtualAddress + sizeOfSection;
}

bool PeLib::ImageLoader::isGoodPagePointer(PFN_VERIFY_ADDRESS PfnVerifyAddress, void * pagePtr)
{
	// If the caller didn't supply a verification procedure, use default one
	// The verification procedure can possibly be system-specific, like IsBadReadPtr on Windows
	if(PfnVerifyAddress == nullptr)
	{
		// In order to work in Windows, it must be built with /EHa
		// (Enable C++ Exceptions: Yes with SEH Exceptions (/EHa))
		try
		{
			uint8_t dummyBuffer[0x10] = {0};
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

bool PeLib::ImageLoader::isGoodMappedPage(uint32_t rva)
{
	uint32_t pageIndex = (rva / PELIB_PAGE_SIZE);

	if(pageIndex > pages.size())
		return false;
	return (pages[pageIndex].isInvalidPage == false);
}

bool PeLib::ImageLoader::isZeroPage(std::uint32_t rva)
{
	uint32_t pageIndex = (rva / PELIB_PAGE_SIZE);

	if(pageIndex > pages.size())
		return false;
	return (pages[pageIndex].isZeroPage);
}

bool PeLib::ImageLoader::isRvaOfSectionHeaderPointerToRawData(uint32_t rva)
{
	uint32_t rvaOfLastSectionPointerToRawData;

	// If there is at least one section
	for(size_t i = 0; i < sections.size(); i++)
	{
		// Get the reference to the section header
		PELIB_IMAGE_SECTION_HEADER & sectHdr = sections[i];

		// Must be a section with SizeOfRawData = 0
		if(sectHdr.SizeOfRawData == 0)
		{
			// Calculate the RVA of the PointerToRawData variable in the last section
			rvaOfLastSectionPointerToRawData = dosHeader.e_lfanew +
				sizeof(uint32_t) +
				sizeof(PELIB_IMAGE_FILE_HEADER) +
				fileHeader.SizeOfOptionalHeader +
				i * sizeof(PELIB_IMAGE_SECTION_HEADER) +
				0x14;		// FIELD_OFFSET(PELIB_IMAGE_SECTION_HEADER, PointerToRawData)

			if(rvaOfLastSectionPointerToRawData <= rva && rva < rvaOfLastSectionPointerToRawData + sizeof(uint32_t))
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

// Windows 10: For IMAGE_FILE_MACHINE_I386 and IMAGE_FILE_MACHINE_AMD64,
// if (Characteristics & IMAGE_FILE_RELOCS_STRIPPED) and (DllCharacteristics & IMAGE_DLLCHARACTERISTICS_APPCONTAINER),
// MiVerifyImageHeader returns STATUS_INVALID_IMAGE_FORMAT.
bool PeLib::ImageLoader::checkForBadAppContainer()
{
	if(isLegacyImageArchitecture(fileHeader.Machine))
	{
		if(optionalHeader.DllCharacteristics & PELIB_IMAGE_DLLCHARACTERISTICS_APPCONTAINER)
		{
			if(fileHeader.Characteristics & PELIB_IMAGE_FILE_RELOCS_STRIPPED)
			{
				return true;
			}
		}
	}

	return false;
}

bool PeLib::ImageLoader::isImageMappedOk()
{
	// If there was loader error, we didn't map the image
	if(ldrError != LDR_ERROR_NONE && ldrError != LDR_ERROR_FILE_IS_CUT_LOADABLE)
		return false;
	if(pages.size() == 0)
		return false;
	return true;
}

//-----------------------------------------------------------------------------
// Testing function

void PeLib::ImageLoader::compareWithWindowsMappedImage(PELIB_IMAGE_COMPARE & ImageCompare, void * imageDataPtr, std::uint32_t imageSize)
{
	uint8_t * winImageData = reinterpret_cast<uint8_t *>(imageDataPtr);
	uint8_t * winImageEnd = winImageData + imageSize;
	uint8_t singlePage[PELIB_PAGE_SIZE];
	size_t mismatchOffset;
	size_t rva = 0;

	// Are both loaded?
	if(winImageData != nullptr && isImageMappedOk())
	{
		// Check whether the image size is the same
		if(imageSize != getSizeOfImageAligned())
		{
			ImageCompare.compareResult = ImagesDifferentSize;
			ImageCompare.differenceOffset = 0;
			return;
		}

		// Compare images page-by-page
		while(winImageData < winImageEnd)
		{
			// If the windows page is inaccessible, our page must be inaccessible as well
			bool isGoodPageWin = isGoodPagePointer(ImageCompare.PfnVerifyAddress, winImageData);
			bool isGoodPageMy  = isGoodMappedPage(rva);

			// Both are accessible -> Compare the page
			if(isGoodPageWin && isGoodPageMy)
			{
				// Read the image page
				readImage(singlePage, rva, sizeof(singlePage));

				// Check for difference
				// Note that if this is done in a debugger (e.g. Visual Studio) and PDB is available,
				// it might place breakpoint to the position of __crt_debugger_hook, which will cause
				// this memcmp return difference.
				if(memcmp(winImageData, singlePage, PELIB_PAGE_SIZE))
				{
					mismatchOffset = getMismatchOffset(winImageData, singlePage, rva, PELIB_PAGE_SIZE);
					if(mismatchOffset != (size_t)(-1))
					{
						ImageCompare.compareResult = ImagesDifferentPageValue;
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
					ImageCompare.compareResult = ImagesDifferentPageAccess;
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
			ImageCompare.compareResult = ImagesWindowsDidntLoadWeDid;
			return;
		}
	}
	else
	{
		// Windows mapped the image
		if(winImageData != nullptr)
		{
			ImageCompare.compareResult = ImagesWindowsLoadedWeDidnt;
			return;
		}
	}

	// Both Windows and our image are the same
	ImageCompare.compareResult = ImagesEqual;
	ImageCompare.differenceOffset = 0;
}
