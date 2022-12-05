/*
* ImageLoader.h - Interface to the PE imaage loader class
*
* Copyright (c) 2020 Ladislav Zezula
* All rights reserved.
*
* This software is licensed under the zlib/libpng License.
* For more details see http://www.opensource.org/licenses/zlib-license.php
* or the license information file (license.htm) in the root directory
* of PeLib.
*/

#ifndef RETDEC_PELIB_IMAGE_LOADER_H
#define RETDEC_PELIB_IMAGE_LOADER_H

#include <string>
#include <vector>

#include "PeLibAux.h"

namespace PeLib {

//-----------------------------------------------------------------------------
// Enum for ImageLoader::getFieldOffset()

enum struct PELIB_MEMBER_TYPE : std::uint32_t
{
	OPTHDR_sizeof,
	OPTHDR_sizeof_fixed,
	OPTHDR_NumberOfRvaAndSizes,
	OPTHDR_DataDirectory,
	OPTHDR_DataDirectory_EXPORT_Rva,
	OPTHDR_DataDirectory_RSRC_Rva,
	OPTHDR_DataDirectory_TLS_Rva,
	OPTHDR_DataDirectory_CONFIG_Rva,
};

//-----------------------------------------------------------------------------
// Support structure for one PE image compare result

enum struct PELIB_COMPARE_RESULT : std::uint32_t
{
	ImagesEqual,                                    // The images are equal
	ImagesWindowsLoadedWeDidnt,                     //
	ImagesWindowsDidntLoadWeDid,                    //
	ImagesDifferentSize,                            // The images have different size
	ImagesDifferentPageAccess,                      // An image page is different (accessible vs non-accessible)
	ImagesDifferentPageValue,                       // There is a different value at a certain offset
	ImagesInvalidPageInImage,                       // A page in the image mapped by Windows is invalid
	ImagesCompareInvalid,
};

//-----------------------------------------------------------------------------
// Windows build numbers

const std::uint32_t BuildNumberXP = 2600;           // Behavior equal to Windows XP
const std::uint32_t BuildNumberVista = 6000;        // Behavior equal to Windows Vista (SP0 = 6000, SP1 = 6001, SP2 = 6002)
const std::uint32_t BuildNumber7 = 7600;            // Behavior equal to Windows 7 (SP0 = 7600, SP1 = 7601)
const std::uint32_t BuildNumber8 = 9200;            // Behavior equal to Windows 8
const std::uint32_t BuildNumber10 = 10240;          // Behavior equal to Windows 10
const std::uint32_t BuildNumberMask = 0x0FFFF;      // Mask for extracting the operating system
const std::uint32_t BuildNumber64Bit = 0x10000;     // Emulate 64-bit system

//-----------------------------------------------------------------------------
// Flags for ImageLoader::Load() and ImageLoader::Save()

const std::uint32_t IoFlagHeadersOnly = 1;          // Only load/save PE headers
const std::uint32_t IoFlagNewFile     = 2;          // Create the PE as new file (for unpackers)
const std::uint32_t IoFlagLoadAsImage = 4;          // Load the data as mapped image file

//-----------------------------------------------------------------------------
// Structure for comparison with Windows mapped images

typedef bool (*PFN_VERIFY_ADDRESS)(void * ptr, size_t length);
typedef bool (*PFN_COMPARE_CALLBACK)(struct PELIB_IMAGE_COMPARE * pImgCompare, size_t BytesCompared, size_t BytesTotal);

struct PELIB_IMAGE_COMPARE
{
	PFN_VERIFY_ADDRESS PfnVerifyAddress = nullptr;  // Custom function for verifying memory address
	PFN_COMPARE_CALLBACK PfnCompareCallback = nullptr; // Custom function for calling compare callback
	PELIB_COMPARE_RESULT compareResult = PELIB_COMPARE_RESULT::ImagesCompareInvalid;
	const char * szFileName = nullptr;              // Current file being compared (plain name)
	const char * dumpIfNotEqual = nullptr;          // If non-NULL, the image will be dumped into that file if different
	std::uint32_t differenceOffset = 0;             // If compareResult is ImagesDifferentPageValue, this contains offset of the difference
	std::uint32_t startTickCount = 0;               // GetTickCount value at the start of image testing
};

//-----------------------------------------------------------------------------
// Support structure for one PE file page

struct PELIB_FILE_PAGE
{
	PELIB_FILE_PAGE()
	{
		isInvalidPage = true;
		isZeroPage = false;
	}

	// Initializes the page with a valid data
	bool setValidPage(const void * data, size_t length)
	{
		// Write the valid data to the page
		writeToPage(data, 0, length);

		// Write zero data to the end of the page
		memset(buffer.data() + length, 0, PELIB_PAGE_SIZE - length);

		isInvalidPage = false;
		isZeroPage = false;
		return true;
	}

	// Initializes the page as zero page. To save memory, we won't initialize buffer
	void setZeroPage()
	{
		buffer.clear();
		isInvalidPage = false;
		isZeroPage = true;
	}

	void writeToPage(const void * data, size_t offset, size_t length)
	{
		if(offset < PELIB_PAGE_SIZE)
		{
			// Make sure that there is buffer allocated
			if(buffer.size() != PELIB_PAGE_SIZE)
				buffer.resize(PELIB_PAGE_SIZE);

			// Copy the data, up to page size
			if((offset + length) > PELIB_PAGE_SIZE)
				length = PELIB_PAGE_SIZE - offset;
			memcpy(buffer.data() + offset, data, length);
		}
	}

	ByteBuffer buffer;                    // A page-sized buffer, holding one image page. Empty if isInvalidPage
	bool isInvalidPage;                   // For invalid pages within image (SectionAlignment > 0x1000)
	bool isZeroPage;                      // For sections with VirtualSize != 0, RawSize = 0
};

//-----------------------------------------------------------------------------
// Image loader class interface

class ImageLoader
{
	public:

	ImageLoader(std::uint32_t loaderFlags = 0);

	int Load(ByteBuffer & fileData, std::uint32_t loadFlags = 0);
	int Load(std::istream & fs, std::streamoff fileOffset = 0, std::uint32_t loadFlags = 0);
	int Load(const char * fileName, std::uint32_t loadFlags = 0);

	int Save(std::ostream & fs, std::streamoff fileOffset = 0, std::uint32_t saveFlags = 0);
	int Save(const char * fileName, std::uint32_t saveFlags = 0);

	bool relocateImage(std::uint64_t newImageBase);

	std::uint32_t readImage(void * buffer, std::uint32_t rva, std::uint32_t bytesToRead);
	std::uint32_t writeImage(void * buffer, std::uint32_t rva, std::uint32_t bytesToRead);

	std::uint32_t readString(std::string & str, std::uint32_t rva, std::uint32_t maxLength = 65535);
	std::uint32_t readStringRc(std::string & str, std::uint32_t rva);
	std::uint32_t readStringRaw(ByteBuffer & fileData,
		                        std::string & str,
		                        std::size_t offset,
		                        std::size_t maxLength = 65535,
		                        bool mustBePrintable = false,
		                        bool mustNotBeTooLong = false);
	std::uint32_t stringLength(std::uint32_t rva, std::uint32_t maxLength = 65535) const;

	std::uint32_t readPointer(std::uint32_t rva, std::uint64_t & pointerValue);
	std::uint32_t getPointerSize() const;

	std::uint32_t dumpImage(const char * fileName);

	std::uint32_t getImageBitability() const;

	std::uint32_t vaToRva(std::uint64_t VirtualAddress) const;
	std::uint32_t getFileOffsetFromRva(std::uint32_t rva) const;
	std::uint32_t getValidOffsetFromRva(std::uint32_t rva) const;
	std::uint32_t getRealPointerToRawData(std::size_t sectionIndex) const;
	std::uint32_t getRealSizeOfRawData(std::size_t sectionIndex) const;
	std::uint32_t getImageProtection(std::uint32_t characteristics) const;
	std::size_t   getSectionIndexByRva(std::uint32_t Rva) const;

	std::uint32_t getFieldOffset(PELIB_MEMBER_TYPE field) const;

	const PELIB_IMAGE_DOS_HEADER & getDosHeader() const
	{
		return dosHeader;
	}

	const PELIB_IMAGE_FILE_HEADER & getFileHeader() const
	{
		return fileHeader;
	}

	const PELIB_IMAGE_OPTIONAL_HEADER & getOptionalHeader() const
	{
		return optionalHeader;
	}

	const PELIB_SECTION_HEADER * getSectionHeader(std::size_t sectionIndex) const
	{
		return (sectionIndex < sections.size()) ? &sections[sectionIndex] : nullptr;
	}

	PELIB_SECTION_HEADER * getSectionHeader(std::size_t sectionIndex)
	{
		return (sectionIndex < sections.size()) ? &sections[sectionIndex] : nullptr;
	}

	std::uint64_t getSizeOfFile() const
	{
		return savedFileSize;
	}

	std::uint64_t getOrdinalMask() const
	{
		return (uint64_t)1 << (getImageBitability() - 1);
	}

	std::uint32_t getPeHeaderOffset() const
	{
		return dosHeader.e_lfanew;
	}

	void setPeHeaderOffset(std::uint32_t new_e_lfanew)
	{
		dosHeader.e_lfanew = new_e_lfanew;
	}

	std::uint32_t getNtSignature() const
	{
		return ntSignature;
	}

	std::uint32_t getMachine() const
	{
		return fileHeader.Machine;
	}

	std::uint32_t getPointerToSymbolTable() const
	{
		return fileHeader.PointerToSymbolTable;
	}

	std::uint32_t getNumberOfSymbols() const
	{
		return fileHeader.NumberOfSymbols;
	}

	std::uint32_t getLoadedNumberOfSections() const
	{
		return fileHeader.NumberOfSections;
	}

	std::uint32_t getCharacteristics() const
	{
		return fileHeader.Characteristics;
	}

	std::uint32_t getNumberOfSections() const
	{
		return sections.size();
	}

	std::uint32_t getMagic() const
	{
		return optionalHeader.Magic;
	}

	std::uint64_t getImageBase() const
	{
		return optionalHeader.ImageBase;
	}

	std::uint32_t getAddressOfEntryPoint() const
	{
		return optionalHeader.AddressOfEntryPoint;
	}

	std::uint32_t getSizeOfHeaders() const
	{
		return optionalHeader.SizeOfHeaders;
	}

	std::uint32_t getSizeOfImage() const
	{
		return optionalHeader.SizeOfImage;
	}

	std::uint32_t getSizeOfImageAligned() const
	{
		return AlignToSize(optionalHeader.SizeOfImage, PELIB_PAGE_SIZE);
	}

	std::uint32_t getSectionAlignment() const
	{
		return optionalHeader.SectionAlignment;
	}

	std::uint32_t getFileAlignment() const
	{
		return optionalHeader.FileAlignment;
	}

	std::uint32_t getChecksumFileOffset() const
	{
		return checkSumFileOffset;
	}

	std::uint32_t getRealNumberOfDataDirectories() const
	{
		return realNumberOfRvaAndSizes;
	}

	std::uint32_t getSecurityDirFileOffset() const
	{
		return securityDirFileOffset;
	}

	std::uint32_t getDataDirRva(std::uint64_t dataDirIndex) const
	{
		// The data directory must be present there
		return (optionalHeader.NumberOfRvaAndSizes > dataDirIndex) ? optionalHeader.DataDirectory[dataDirIndex].VirtualAddress : 0;
	}

	std::uint32_t getDataDirSize(std::uint64_t dataDirIndex) const
	{
		// The data directory must be present there
		return (optionalHeader.NumberOfRvaAndSizes > dataDirIndex) ? optionalHeader.DataDirectory[dataDirIndex].Size : 0;
	}

	std::uint32_t getComDirRva() const
	{
		// For 32-bit binaries, the COM directory is valid even if NumberOfRvaAndSizes < IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
		// Sample: 58b0147d7dd3cd73cb8bf8df077e244650621174f7ff788ad06fd0c1f82aac40
		if(optionalHeader.Magic == PELIB_IMAGE_NT_OPTIONAL_HDR32_MAGIC)
			return optionalHeader.DataDirectory[PELIB_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;
		return getDataDirRva(PELIB_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
	}

	std::uint32_t getComDirSize() const
	{
		// For 32-bit binaries, the COM directory is valid even if NumberOfRvaAndSizes < IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR
		// Sample: 58b0147d7dd3cd73cb8bf8df077e244650621174f7ff788ad06fd0c1f82aac40
		if(optionalHeader.Magic == PELIB_IMAGE_NT_OPTIONAL_HDR32_MAGIC)
			return optionalHeader.DataDirectory[PELIB_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size;
		return getDataDirSize(PELIB_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR);
	}

	std::uint64_t getVirtualAddressMasked(std::uint32_t rva)
	{
		std::uint64_t virtualAddress = getImageBase() + rva;

		if(getImageBitability() == 32)
			virtualAddress = virtualAddress & 0xFFFFFFFF;
		return virtualAddress;
	}

	// Image manipulation
	void setPointerToSymbolTable(std::uint32_t pointerToSymbolTable);
	void setCharacteristics(std::uint32_t characteristics);
	void setAddressOfEntryPoint(std::uint32_t addressOfEntryPoint);
	void setSizeOfCode(std::uint32_t sizeOfCode, std::uint32_t baseOfCode = UINT32_MAX);
	void setDataDirectory(std::uint32_t entryIndex, std::uint32_t VirtualAddress, std::uint32_t Size = UINT32_MAX);

	PELIB_IMAGE_SECTION_HEADER * addSection(const char * name, std::uint32_t size);
	void calcNewSectionAddresses(std::uint32_t & Rva, std::uint32_t & RawOffset);
	void setSectionName(std::size_t sectionIndex, const char * newName);
	void setSectionVirtualRange(std::size_t sectionIndex, std::uint32_t VirtualAddress, std::uint32_t VirtualSize = UINT32_MAX);
	void setSectionRawDataRange(std::size_t sectionIndex, std::uint32_t PointerToRawData, std::uint32_t SizeOfRawData = UINT32_MAX);
	void setSectionCharacteristics(std::size_t sectionIndex, std::uint32_t Characteristics);
	int  splitSection(std::size_t sectionIndex, const std::string & prevSectName, const std::string & nextSectName, std::uint32_t splitOffset);
	void enlargeLastSection(std::uint32_t sectionSize);
	int  removeSection(std::size_t sizeIncrement);
	void makeValid();

	int setLoaderError(LoaderError ldrErr);
	LoaderError loaderError() const;

	// Testing functions
	std::size_t getMismatchOffset(void * buffer1, void * buffer2, std::uint32_t rva, std::size_t length);
	void compareWithWindowsMappedImage(PELIB_IMAGE_COMPARE & ImageCompare, void * imageData, std::uint32_t imageSize);

	protected:

	typedef void (*READWRITE)(PeLib::PELIB_FILE_PAGE & page, void * buffer, std::size_t offsetInPage, std::size_t bytesInPage);

	static void readFromPage(PELIB_FILE_PAGE & page, void * buffer, size_t offsetInPage, size_t bytesInPage);
	static void writeToPage(PELIB_FILE_PAGE & page, void * buffer, size_t offsetInPage, size_t bytesInPage);
	std::uint32_t readWriteImage(void * buffer, std::uint32_t rva, std::uint32_t bytesToRead, READWRITE ReadWrite);
	std::uint32_t readWriteImageFile(void * buffer, std::uint32_t rva, std::uint32_t bytesToRead, bool bReadOperation);

	void processSectionHeader(PELIB_IMAGE_SECTION_HEADER * pSectionHeader);
	bool processImageRelocation_IA64_IMM64(std::uint32_t fixupAddress, std::uint64_t difference);
	bool processImageRelocations(std::uint64_t oldImageBase, std::uint64_t getImageBase, std::uint32_t VirtualAddress, std::uint32_t Size);
	void writeNewImageBase(std::uint64_t newImageBase);

	int captureDosHeader(ByteBuffer & fileData);
	int saveToFile(std::ostream & fs, std::streamoff fileOffset, std::size_t rva, std::size_t length);
	int saveDosHeaderNew(std::ostream & fs, std::streamoff fileOffset);
	int saveDosHeader(std::ostream & fs, std::streamoff fileOffset);
	int captureNtHeaders(ByteBuffer & fileData);
	int saveNtHeadersNew(std::ostream & fs, std::streamoff fileOffset);
	int saveNtHeaders(std::ostream & fs, std::streamoff fileOffset);
	int captureSectionName(ByteBuffer & fileData, std::string & sectionName, const std::uint8_t * name);
	int captureSectionHeaders(ByteBuffer & fileData);
	int saveSectionHeadersNew(std::ostream & fs, std::streamoff fileOffset);
	int saveSectionHeaders(std::ostream & fs, std::streamoff fileOffset);
	int captureImageSections(ByteBuffer & fileData, std::uint32_t loadFlags);
	int captureOptionalHeader32(std::uint8_t * fileData, std::uint8_t * filePtr, std::uint8_t * fileEnd);
	int captureOptionalHeader64(std::uint8_t * fileData, std::uint8_t * filePtr, std::uint8_t * fileEnd);
	std::uint32_t copyDataDirectories(std::uint8_t * optionalHeaderPtr, std::uint8_t * dataDirectoriesPtr, std::size_t optionalHeaderMax, std::uint32_t numberOfRvaAndSizes);

	int verifyDosHeader(PELIB_IMAGE_DOS_HEADER & hdr, std::size_t fileSize);
	int verifyDosHeader(std::istream & fs, std::streamoff fileOffset, std::size_t fileSize);

	int loadImageAsIs(ByteBuffer & fileData);

	std::uint32_t captureImageSection(ByteBuffer & fileData,
									  std::uint32_t virtualAddress,
									  std::uint32_t virtualSize,
									  std::uint32_t pointerToRawData,
									  std::uint32_t sizeOfRawData,
									  std::uint32_t characteristics,
									  bool isImageHeader = false);

	bool isGoodPagePointer(PFN_VERIFY_ADDRESS PfnVerifyAddress, void * pagePtr);
	bool isGoodMappedPage(std::uint32_t rva);
	bool isZeroPage(std::uint32_t rva);

	bool isSectionHeaderPointerToRawData(uint32_t rva);
	bool isLegacyImageArchitecture(std::uint16_t Machine);
	bool checkForValid64BitMachine();
	bool checkForValid32BitMachine();
	bool checkForInvalidImageRange();
	bool isValidMachineForCodeIntegrifyCheck(std::uint32_t Bits);
	bool checkForSectionTablesWithinHeader(std::uint32_t e_lfanew);
	bool checkForBadCodeIntegrityImages(ByteBuffer & fileData);
	bool checkForBadArchitectureSpecific();
	bool checkForImageAfterMapping();

	template <typename LOAD_CONFIG>
	bool checkForBadLoadConfigXX(std::uint32_t loadConfigRva, std::uint32_t loadConfigSize);

	// isImageLoadable returns true if the image is OK and can be mapped by NtCreateSection(SEC_IMAGE).
	// This does NOT mean that the image is executable by CreateProcess - more checks are done,
	// like resource integrity or relocation table correctness.
	bool isImageLoadable() const;
	bool isImageMappedOk() const;
	bool isValidImageBlock(std::uint32_t Rva, std::uint32_t Size)  const;

	static std::uint32_t AlignToSize(std::uint32_t ByteSize, std::uint32_t AlignSize)
	{
		return ((ByteSize + (AlignSize - 1)) & ~(AlignSize - 1));
	}

	static std::uint32_t BytesToPages(std::uint32_t ByteSize)
	{
		return (ByteSize >> PELIB_PAGE_SIZE_SHIFT) + ((ByteSize & (PELIB_PAGE_SIZE - 1)) != 0);
	}

	static std::uint64_t signExtend32To64(std::uint32_t value32)
	{
		return (std::uint64_t)(std::int64_t)(std::int32_t)value32;
	}

	// Anti-assert feature. Debug version of isprint in MS Visual C++ asserts
	// when the character is not EOF or is >= 255
	bool isPrintableChar(int ch)
	{
		return ((EOF <= ch) && (ch <= 255)) ? isprint(ch) : false;
	}

	static uint8_t ImageProtectionArray[16];

	std::vector<PELIB_SECTION_HEADER> sections;         // Vector of section headers
	std::vector<PELIB_FILE_PAGE> pages;                 // PE file pages as if mapped
	PELIB_IMAGE_DOS_HEADER  dosHeader;                  // Loaded DOS header
	PELIB_IMAGE_FILE_HEADER fileHeader;                 // Loaded NT file header
	PELIB_IMAGE_OPTIONAL_HEADER optionalHeader;         // 32/64-bit optional header
	ByteBuffer rawFileData;                             // Loaded content of the image in case it couldn't have been mapped
	LoaderError ldrError;
	std::uint64_t savedFileSize;                        // Size of the raw file
	std::uint32_t windowsBuildNumber;
	std::uint32_t ntSignature;
	std::uint32_t maxSectionCount;
	std::uint32_t realNumberOfRvaAndSizes;              // Real present number of RVA and sizes
	std::uint32_t checkSumFileOffset;                   // File offset of the image checksum
	std::uint32_t securityDirFileOffset;                // File offset of security directory
	std::uint32_t ssiImageAlignment32;                  // Alignment of signle-section images under 32-bit OS
	bool is64BitWindows;                                // If true, we simulate 64-bit Windows
	bool ntHeadersSizeCheck;                            // If true, the loader requires minimum size of NT headers
	bool sizeofImageMustMatch;                          // If true, the SizeOfImage must match virtual end of the last section
	bool architectureSpecificChecks;                    // If true, architecture-specific checks are also performed
	bool headerSizeCheck;                               // If true, image loader will imitate Windows XP header size check
	bool loadArmImages;                                 // If true, image loader will load ARM binaries
	bool loadArm64Images;                               // If true, image loader will load ARM64 binaries
	bool loadItaniumImages;                             // If true, image loader will load IA64 binaries
	bool forceIntegrityCheckEnabled;                    // If true, extra checks will be done if IMAGE_DLLCHARACTERISTICS_FORCE_INTEGRITY is set
	bool forceIntegrityCheckCertificate;                // If true, extra check for certificate will be provided
	bool checkNonLegacyDllCharacteristics;              // If true, extra checks will be performed on DllCharacteristics
	bool checkImagePostMapping;                         // If true, extra checks will be performed after the image is mapped
	bool alignSingleSectionImagesToPage;                // Align single-section images to page size in 64-bit windows
};

}	// namespace PeLib

#endif	// RETDEC_PELIB_IMAGE_LOADER_H
