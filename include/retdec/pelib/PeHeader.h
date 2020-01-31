/*
* PeHeader.h - Part of the PeLib library.
*
* Copyright (c) 2004 - 2005 Sebastian Porst (webmaster@the-interweb.com)
* All rights reserved.
*
* This software is licensed under the zlib/libpng License.
* For more details see http://www.opensource.org/licenses/zlib-license.php
* or the license information file (license.htm) in the root directory
* of PeLib.
*/

#ifndef PEHEADER_H
#define PEHEADER_H

#include <algorithm>
#include <string.h>

#include "pelib/PeLibAux.h"
#include "pelib/MzHeader.h"

namespace PeLib
{
	class PeHeader
	{
//		protected:
//			virtual void readBaseOfData(InputBuffer& ibBuffer) = 0;
//			virtual void rebuildBaseOfData(OutputBuffer& obBuffer) const = 0;

		public:
			virtual ~PeHeader(){};
	};

	/// Class that handles the PE header of files.
	/**
	* This class can read and modify PE headers. It provides set- and get functions to access
	* all individual members of a PE header. Furthermore it's possible to validate and rebuild
	* PE headers. A PE header includes the IMAGE_Nt_HEADERS and the section definitions of a PE file.
	* \todo getIdReservedRva
	**/
	template<int x>
	class PeHeaderT : public PeHeader
	{
		private:
		  void readBaseOfData(InputBuffer& ibBuffer, PELIB_IMAGE_NT_HEADERS<x>& header) const;
		  void rebuildBaseOfData(OutputBuffer& obBuffer) const;

		protected:
		  std::vector<PELIB_IMAGE_SECTION_HEADER> m_vIsh; ///< Stores section header information.
		  PELIB_IMAGE_NT_HEADERS<x> m_inthHeader; ///< Stores Nt header information.
		  MzHeader m_mzHeader; ///< Stored DOS header.
		  dword m_uiOffset; ///< Equivalent to the value returned by #PeLib::MzHeader::getAddressOfPeFile
		  LoaderError m_ldrError;
		  unsigned long m_checksumFileOffset; ///< File offset of checksum field in optional PE header
		  unsigned long m_secDirFileOffset; ///< File offset of security data directory

		  void setLoaderError(LoaderError ldrError);

		public:
		  typedef typename FieldSizes<x>::VAR4_8 VAR4_8;

		  PeHeaderT() : m_uiOffset(0), m_checksumFileOffset(0), m_secDirFileOffset(0), m_ldrError(LDR_ERROR_NONE)
		  {
		  }

		  LoaderError loaderError() const;

		  /// Add a section to the header.
		  int addSection(const std::string& strName, dword dwSize); // EXPORT

		  // Splits a section into two.
		  int splitSection(word uiSectionnr, const std::string& first, const std::string& second, dword dwSplitOffset); // EXPORT

		  // Removes a section.
		  int removeSection(word uiSectionnr); // EXPORT

		  unsigned int calcSizeOfImage() const; // EXPORT

		  /// Returns the unused space after the header.
		  unsigned int calcSpaceAfterHeader() const; // EXPORT

		  /// Returns the address of the physically first section (not the first defined section).
		  unsigned int calcStartOfCode() const; // EXPORT

		  /// Calculates the offset for a new section of size uiSize.
		  unsigned int calcOffset() const; // EXPORT

		  /// Calculates the Rva for a new section of size uiSize.
		  unsigned int calcRva() const; // EXPORT

		  /// Returns the number of sections in the current file.
		  word calcNumberOfSections() const; // EXPORT

		  void enlargeLastSection(unsigned int uiSize); // EXPORT

		  /// Returns the section Id of the section that contains the offset.
		  word getSectionWithOffset(VAR4_8 dwOffset) const; // EXPORT

		  /// Returns the number of the section which the given relative address points to.
		  word getSectionWithRva(VAR4_8 rva) const; // EXPORT

		  bool isValid() const; // EXPORT
		  bool isValid(unsigned int foo) const; // EXPORT

		  /// Corrects the current PE header.
		  void makeValid(dword dwOffset); // EXPORT

		  /// Converts a file offset to a relative virtual offset.
		  unsigned int offsetToRva(VAR4_8 dwOffset) const; // EXPORT

		  /// Converts a file offset to a virtual address.
		  unsigned int offsetToVa(VAR4_8 dwOffset) const; // EXPORT

		  /// Reads the PE header of a file.
		  int read(
				  std::istream& inStream,
				  unsigned int uiOffset,
				  const MzHeader &mzHeader); // EXPORT

		  void readHeader(InputBuffer& ibBuffer, PELIB_IMAGE_NT_HEADERS<x>& header);
		  void readDataDirectories(
				  std::istream& inStream,
				  unsigned int uiOffset,
				  PELIB_IMAGE_NT_HEADERS<x>& header);
		  std::vector<PELIB_IMAGE_SECTION_HEADER> readSections(
				  std::istream& inStream,
				  unsigned int uiOffset,
				  PELIB_IMAGE_NT_HEADERS<x>& header);

		  /// Rebuilds the current PE header.
		  void rebuild(std::vector<byte>& vBuffer) const; // EXPORT

		  // Checks whether RVA is valid for this image.
		  bool isValidRva(VAR4_8 dwRva) const; // EXPORT

		  /// Converts a relative virtual address to a file offset.
		  VAR4_8 rvaToOffset(VAR4_8 dwRva) const; // EXPORT
		  VAR4_8 rvaToOffsetSpeculative(VAR4_8 dwRva) const; // EXPORT

		  /// Converts a relative virtual address to a virtual address.
		  VAR4_8 rvaToVa(VAR4_8 dwRva) const; // EXPORT

		  /// Calculates the size for the current PE header including all section definitions.
		  unsigned int size() const;

		  VAR4_8 vaToRva(VAR4_8 dwRva) const; // EXPORT
		  VAR4_8 vaToOffset(VAR4_8 dwRva) const; // EXPORT
		  VAR4_8 vaToOffsetSpeculative(VAR4_8 dwRva) const; // EXPORT

		  /// Save the PE header to a file.
		  int write(std::string strFilename, unsigned int uiOffset) const; // EXPORT

		  /// Writes sections to a file.
		  int writeSections(const std::string& strFilename) const; // EXPORT
		  /// Overwrites a section with new data.
		  int writeSectionData(const std::string& strFilename, word wSecnr, const std::vector<byte>& vBuffer) const; // EXPORT

		  /// Returns file offset of checksum field
		  unsigned int getChecksumFileOffset() const; // EXPORT
		  /// Returns file offset of security data directory
		  unsigned int getSecDirFileOffset() const; // EXPORT

// header getters
		  /// Returns reference to NT headers.
		  const PELIB_IMAGE_NT_HEADERS<x>& getNtHeaders() const; // EXPORT
		  /// Returns the Signature value of the header.
		  dword getNtSignature() const; // EXPORT
		  /// Returns the Machine value of the header.
		  word getMachine() const; // EXPORT
		  /// Returns the Sections value of the header.
		  word getNumberOfSections() const; // EXPORT
		  /// Returns the TimeDateStamp value of the header.
		  dword getTimeDateStamp() const; // EXPORT
		  /// Returns the PointerToSymbolTable value of the header.
		  dword getPointerToSymbolTable() const; // EXPORT
		  /// Returns the NumberOfSymbols value of the header.
		  dword getNumberOfSymbols() const; // EXPORT
		  /// Returns the SizeOfOptionalHeader value of the header.
		  word getSizeOfOptionalHeader() const; // EXPORT
		  /// Returns the Characteristics value of the header.
		  word getCharacteristics() const; // EXPORT

		  /// Returns the Magic value of the header.
		  word getMagic() const; // EXPORT
		  /// Returns the MajorLinkerVersion value of the header.
		  byte getMajorLinkerVersion() const; // EXPORT
		  /// Returns the MinorLinkerVersion value of the header.
		  byte getMinorLinkerVersion() const; // EXPORT
		  /// Returns the SizeOfCode value of the header.
		  dword getSizeOfCode() const; // EXPORT
		  /// Returns the SizeOfInitializedData value of the header.
		  dword getSizeOfInitializedData() const; // EXPORT
		  /// Returns the SizeOfUninitializedData value of the header.
		  dword getSizeOfUninitializedData() const; // EXPORT
		  /// Returns the AddressOfEntryPoint value of the header.
		  dword getAddressOfEntryPoint() const; // EXPORT
		  /// Returns the BaseOfCode value of the header.
		  dword getBaseOfCode() const; // EXPORT
		  /// Returns the ImageBase value of the header.
		  VAR4_8 getImageBase() const; // EXPORT
		  /// Returns the SectionAlignment value of the header.
		  dword getSectionAlignment() const; // EXPORT
		  /// Returns the FileAlignment value of the header.
		  dword getFileAlignment() const; // EXPORT
		  /// Returns the MajorOperatingSystemVersion value of the header.
		  word getMajorOperatingSystemVersion() const; // EXPORT
		  /// Returns the MinorOperatingSystemVersion value of the header.
		  word getMinorOperatingSystemVersion() const; // EXPORT
		  /// Returns the MajorImageVersion value of the header.
		  word getMajorImageVersion() const; // EXPORT
		  /// Returns the MinorImageVersion value of the header.
		  word getMinorImageVersion() const; // EXPORT
		  /// Returns the MajorSubsystemVersion value of the header.
		  word getMajorSubsystemVersion() const; // EXPORT
		  /// Returns the MinorSubsystemVersion value of the header.
		  word getMinorSubsystemVersion() const; // EXPORT
		  /// Returns the Reserved1 value of the header.
		  dword getWin32VersionValue() const; // EXPORT
		  /// Returns the SizeOfImage value of the header.
		  dword getSizeOfImage() const; // EXPORT
		  /// Returns the SizeOfHeaders value of the header.
		  dword getSizeOfHeaders() const; // EXPORT
		  /// Returns the CheckSum value of the header.
		  dword getCheckSum() const; // EXPORT
		  /// Returns the Subsystem value of the header.
		  word getSubsystem() const; // EXPORT
		  /// Returns the DllCharacteristics value of the header.
		  word getDllCharacteristics() const; // EXPORT
		  /// Returns the SizeOfStackReserve value of the header.
		  VAR4_8 getSizeOfStackReserve() const; // EXPORT
		  /// Returns the SizeOfStackCommit value of the header.
		  VAR4_8 getSizeOfStackCommit() const; // EXPORT
		  /// Returns the SizeOfHeapReserve value of the header.
		  VAR4_8 getSizeOfHeapReserve() const; // EXPORT
		  /// Returns the SizeOfHeapCommit value of the header.
		  VAR4_8 getSizeOfHeapCommit() const; // EXPORT
		  /// Returns the LoaderFlags value of the header.
		  dword getLoaderFlags() const; // EXPORT
		  /// Returns the NumberOfRvaAndSizes value of the header.
		  dword getNumberOfRvaAndSizes() const; // EXPORT
		  dword calcNumberOfRvaAndSizes() const; // EXPORT

		  void addDataDirectory(); // EXPORT
		  void removeDataDirectory(dword index); // EXPORT

// image directory getters
		  /// Returns the relative virtual address of the image directory Export.
		  dword getIddExportRva() const; // EXPORT
		  /// Returns the size of the image directory Export.
		  dword getIddExportSize() const; // EXPORT
		  /// Returns the relative virtual address of the image directory Import.
		  dword getIddImportRva() const; // EXPORT
		  /// Returns the size of the image directory Import.
		  dword getIddImportSize() const; // EXPORT
		  /// Returns the relative virtual address of the image directory Resource.
		  dword getIddResourceRva() const; // EXPORT
		  /// Returns the size of the image directory Resource.
		  dword getIddResourceSize() const; // EXPORT
		  /// Returns the relative virtual address of the image directory Exception.
		  dword getIddExceptionRva() const; // EXPORT
		  /// Returns the size of the image directory Exception.
		  dword getIddExceptionSize() const; // EXPORT
		  /// Returns the relative virtual address of the image directory Security.
		  dword getIddSecurityRva() const; // EXPORT
		  /// Returns the size of the image directory Security.
		  dword getIddSecuritySize() const; // EXPORT
		  /// Returns the relative virtual address of the image directory Base Reloc.
		  dword getIddBaseRelocRva() const; // EXPORT
		  /// Returns the size of the image directory Base Reloc.
		  dword getIddBaseRelocSize() const; // EXPORT
		  /// Returns the relative virtual address of the image directory Debug.
		  dword getIddDebugRva() const; // EXPORT
		  /// Returns the size of the image directory Debug.
		  dword getIddDebugSize() const; // EXPORT
		  /// Returns the relative virtual address of the image directory Architecture.
		  dword getIddArchitectureRva() const; // EXPORT
		  /// Returns the size of the image directory Architecture.
		  dword getIddArchitectureSize() const; // EXPORT
		  /// Returns the relative virtual address of the image directory GlobalPtr.
		  dword getIddGlobalPtrRva() const; // EXPORT
		  /// Returns the size of the image directory GlobalPtr.
		  dword getIddGlobalPtrSize() const; // EXPORT
		  /// Returns the relative virtual address of the image directory Tls.
		  dword getIddTlsRva() const; // EXPORT
		  /// Returns the size of the image directory Tls.
		  dword getIddTlsSize() const; // EXPORT
		  /// Returns the relative virtual address of the image directory LoadConfig.
		  dword getIddLoadConfigRva() const; // EXPORT
		  /// Returns the size of the image directory LoadConfig.
		  dword getIddLoadConfigSize() const; // EXPORT
		  /// Returns the relative virtual address of the image directory BoundImport.
		  dword getIddBoundImportRva() const; // EXPORT
		  /// Returns the size of the image directory BoundImport.
		  dword getIddBoundImportSize() const; // EXPORT
		  /// Returns the relative virtual address of the image directory Iat.
		  dword getIddIatRva() const; // EXPORT
		  /// Returns the size of the image directory Iat.
		  dword getIddIatSize() const; // EXPORT
		  /// Returns the relative virtual address of the image directory DelayImport.
		  dword getIddDelayImportRva() const; // EXPORT
		  /// Returns the size of the image directory DelayImport.
		  dword getIddDelayImportSize() const; // EXPORT
		  /// Returns the relative virtual address of the image directory COM Descriptor.
		  dword getIddComHeaderRva() const; // EXPORT
		  /// Returns the size of the image directory COM Descriptor.
		  dword getIddComHeaderSize() const; // EXPORT

		  /// Returns the relative virtual address of an image directory.
		  dword getImageDataDirectoryRva(dword dwDirectory) const; // EXPORT
		  /// Returns the size of an image directory.
		  dword getImageDataDirectorySize(dword dwDirectory) const; // EXPORT

		  void setImageDataDirectoryRva(dword dwDirectory, dword value); // EXPORT
		  void setImageDataDirectorySize(dword dwDirectory, dword value); // EXPORT

// section getters
		  /// Returns the name of a section.
		  std::string getSectionName(word uiSectionnr) const; // EXPORT
		  // Returns the name of a section stored in string table
		  std::string getSectionNameFromStringTable(word uiSectionnr) const; // EXPORT
		  /// Returns the virtual size of a section.
		  dword getVirtualSize(word uiSectionnr) const; // EXPORT
		  /// Returns the virtual address of a section.
		  dword getVirtualAddress(word uiSectionnr) const; // EXPORT
		  /// Returns the size of a section's raw data.
		  dword getSizeOfRawData(word uiSectionnr) const; // EXPORT
		  /// Returns file offset of the data of a section.
		  dword getPointerToRawData(word uiSectionnr) const; // EXPORT
		  /// Returns the rva of the relocations of a section.
		  dword getPointerToRelocations(word uiSectionnr) const; // EXPORT
		  /// Returns the rva of the line numbers of a section.
		  dword getPointerToLinenumbers(word uiSectionnr) const; // EXPORT
		  /// Returns the number of relocations of a section.
		  dword getNumberOfRelocations(word uiSectionnr) const; // EXPORT
		  /// Returns the number of line numbers of a section.
		  dword getNumberOfLinenumbers(word uiSectionnr) const; // EXPORT
		  /// Returns the characteristics of a section.
		  dword getCharacteristics(word uiSectionnr) const; // EXPORT _section

// header setters
		  /// Sets the Signature value of the header.
		  void setNtSignature(dword value); // EXPORT
		  /// Sets the Machine value of the header.
		  void setMachine(word value); // EXPORT
		  /// Sets the Sections value of the header.
		  void setNumberOfSections(word value); // EXPORT
		  /// Sets the TimeDateStamp value of the header.
		  void setTimeDateStamp(dword value); // EXPORT
		  /// Sets the PointerToSymbolTable value of the header.
		  void setPointerToSymbolTable(dword value); // EXPORT
		  /// Sets the NumberOfSymbols value of the header.
		  void setNumberOfSymbols(dword value); // EXPORT
		  /// Sets the SizeOfOptionalHeader value of the header.
		  void setSizeOfOptionalHeader(word value); // EXPORT
		  /// Sets the Characteristics value of the header.
		  void setCharacteristics(word value); // EXPORT _section

		  /// Sets the Magic value of the header.
		  void setMagic(word value); // EXPORT
		  /// Sets the MajorLinkerVersion value of the header.
		  void setMajorLinkerVersion(byte value); // EXPORT
		  /// Sets the MinorLinkerVersion value of the header.
		  void setMinorLinkerVersion(byte value); // EXPORT
		  /// Sets the SizeOfCode value of the header.
		  void setSizeOfCode(dword value); // EXPORT
		  /// Sets the SizeOfInitializedData value of the header.
		  void setSizeOfInitializedData(dword value); // EXPORT
		  /// Sets the SizeOfUninitializedData value of the header.
		  void setSizeOfUninitializedData(dword value); // EXPORT
		  /// Sets the AddressOfEntryPoint value of the header.
		  void setAddressOfEntryPoint(dword value); // EXPORT
		  /// Sets the BaseOfCode value of the header.
		  void setBaseOfCode(dword value); // EXPORT
		  /// Sets the ImageBase value of the header.
		  void setImageBase(VAR4_8 value); // EXPORT
		  /// Sets the SectionAlignment value of the header.
		  void setSectionAlignment(dword value); // EXPORT
		  /// Sets the FileAlignment value of the header.
		  void setFileAlignment(dword value); // EXPORT
		  /// Sets the MajorOperatingSystemVersion value of the header.
		  void setMajorOperatingSystemVersion(word value); // EXPORT
		  /// Sets the MinorOperatingSystemVersion value of the header.
		  void setMinorOperatingSystemVersion(word value); // EXPORT
		  /// Sets the MajorImageVersion value of the header.
		  void setMajorImageVersion(word value); // EXPORT
		  /// Sets the MinorImageVersion value of the header.
		  void setMinorImageVersion(word value); // EXPORT
		  /// Sets the MajorSubsystemVersion value of the header.
		  void setMajorSubsystemVersion(word value); // EXPORT
		  /// Sets the MinorSubsystemVersion value of the header.
		  void setMinorSubsystemVersion(word value); // EXPORT
		  /// Sets the Reserved1 value of the header.
		  void setWin32VersionValue(dword value); // EXPORT
		  /// Sets the SizeOfImage value of the header.
		  void setSizeOfImage(dword value); // EXPORT
		  /// Sets the SizeOfHeaders value of the header.
		  void setSizeOfHeaders(dword value); // EXPORT
		  /// Sets the CheckSum value of the header.
		  void setCheckSum(dword value); // EXPORT
		  /// Sets the Subsystem value of the header.
		  void setSubsystem(word value); // EXPORT
		  /// Sets the DllCharacteristics value of the header.
		  void setDllCharacteristics(word value); // EXPORT
		  /// Sets the SizeOfStackReserve value of the header.
		  void setSizeOfStackReserve(VAR4_8 value); // EXPORT
		  /// Sets the SizeOfStackCommit value of the header.
		  void setSizeOfStackCommit(VAR4_8 value); // EXPORT
		  /// Sets the SizeOfHeapReserve value of the header.
		  void setSizeOfHeapReserve(VAR4_8 value); // EXPORT
		  /// Sets the SizeOfHeapCommit value of the header.
		  void setSizeOfHeapCommit(VAR4_8 value); // EXPORT
		  /// Sets the LoaderFlags value of the header.
		  void setLoaderFlags(dword value); // EXPORT
		  /// Sets the NumberOfRvaAndSizes value of the header.
		  void setNumberOfRvaAndSizes(dword value); // EXPORT

// image directory getters
		  void setIddDebugRva(dword dwValue); // EXPORT
		  void setIddDebugSize(dword dwValue); // EXPORT
		  void setIddDelayImportRva(dword dwValue); // EXPORT
		  void setIddDelayImportSize(dword dwValue); // EXPORT
		  void setIddExceptionRva(dword dwValue); // EXPORT
		  void setIddExceptionSize(dword dwValue); // EXPORT
		  void setIddGlobalPtrRva(dword dwValue); // EXPORT
		  void setIddGlobalPtrSize(dword dwValue); // EXPORT
		  void setIddIatRva(dword dwValue); // EXPORT
		  void setIddIatSize(dword dwValue); // EXPORT
		  void setIddLoadConfigRva(dword dwValue); // EXPORT
		  void setIddLoadConfigSize(dword dwValue); // EXPORT
		  void setIddResourceRva(dword dwValue); // EXPORT
		  void setIddResourceSize(dword dwValue); // EXPORT
		  void setIddSecurityRva(dword dwValue); // EXPORT
		  void setIddSecuritySize(dword dwValue); // EXPORT
		  void setIddTlsRva(dword dwValue); // EXPORT
		  void setIddTlsSize(dword dwValue); // EXPORT

		  void setIddImportRva(dword dwValue); // EXPORT
		  void setIddImportSize(dword dwValue); // EXPORT
		  void setIddExportRva(dword dwValue); // EXPORT
		  void setIddExportSize(dword dwValue); // EXPORT

		  void setIddBaseRelocRva(dword value); // EXPORT
		  void setIddBaseRelocSize(dword value); // EXPORT
		  void setIddArchitectureRva(dword value); // EXPORT
		  void setIddArchitectureSize(dword value); // EXPORT
		  void setIddComHeaderRva(dword value); // EXPORT
		  void setIddComHeaderSize(dword value); // EXPORT

		  /// Set the name of a section.
		  void setSectionName(word uiSectionnr, std::string strName); // EXPORT
		  /// Set the virtual size of a section.
		  void setVirtualSize(word uiSectionnr, dword dwValue); // EXPORT
		  /// Set the virtual address of a section.
		  void setVirtualAddress(word uiSectionnr, dword dwValue); // EXPORT
		  /// Set the size of raw data of a section.
		  void setSizeOfRawData(word uiSectionnr, dword dwValue); // EXPORT
		  /// Set the file offset of a section.
		  void setPointerToRawData(word uiSectionnr, dword dwValue); // EXPORT
		  /// Set the pointer to relocations of a section.
		  void setPointerToRelocations(word uiSectionnr, dword dwValue); // EXPORT
		  /// Set the pointer to linenumbers of a section.
		  void setPointerToLinenumbers(word uiSectionnr, dword dwValue); // EXPORT
		  /// Set the number of relocations a section.
		  void setNumberOfRelocations(word uiSectionnr, dword dwValue); // EXPORT
		  /// Set the number of linenumbers section.
		  void setNumberOfLinenumbers(word uiSectionnr, dword dwValue); // EXPORT
		  /// Set the characteristics of a section.
		  void setCharacteristics(word uiSectionnr, dword dwValue); // EXPORT
	};

	class PeHeader32 : public PeHeaderT<32>
	{
		public:
		  /// Returns the BaseOfData value of the header.
		  dword getBaseOfData() const; // EXPORT
		  /// Sets the BaseOfData value of the header.
		  void setBaseOfData(dword value); // EXPORT
	};

	class PeHeader64 : public PeHeaderT<64>
	{
	};

	template<int x>
	void PeHeaderT<x>::addDataDirectory()
	{
		m_inthHeader.dataDirectories.push_back(PELIB_IMAGE_DATA_DIRECTORY());
	}

	template<int x>
	void PeHeaderT<x>::removeDataDirectory(dword index)
	{
		if (m_inthHeader.lastDirectoryIsIncomplete && index == m_inthHeader.dataDirectories.size() - 1)
		{
			m_inthHeader.lastDirectoryIsIncomplete = false;
		}
		m_inthHeader.dataDirectories.erase(m_inthHeader.dataDirectories.begin() + index);
	}

	/**
	* Adds a new section to the header. The physical and virtual address as well as the virtual
	* size of the section will be determined automatically from the raw size. The section
	* characteristics will be set to IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ |
	* IMAGE_SCN_CNT_INITIALIZED_DATA | IMAGE_SCN_CNT_CODE. All other values will be set to 0.
	* Note: It's important that if the current header's FileAlignment and/or SectionAlignment values are
	* 0 this function will fail.
	* @param strName Name of the new section. If this name is longer than 8 bytes only the first 8 bytes will be used.
	* @param dwSize Physical size of the new section in bytes.
	* \todo Better code that handles files with 0 sections.
	**/
	template<int x>
	int PeHeaderT<x>::addSection(const std::string& strName, dword dwSize)
	{
		unsigned int uiSecnr = calcNumberOfSections();

		if (!getFileAlignment())
		{
			return ERROR_NO_FILE_ALIGNMENT;
		}
		else if (!getSectionAlignment())
		{
			return ERROR_NO_SECTION_ALIGNMENT;
		}

		if (uiSecnr) // Always allow 1 section.
		{
			if (uiSecnr == 0xFFFF)
			{
				return ERROR_TOO_MANY_SECTIONS;
			}
		}

		dword dwOffset = calcOffset(/*dwSize*/);
		dword dwRva = calcRva(/*dwSize*/);

		PELIB_IMAGE_SECTION_HEADER ishdCurr;
		m_vIsh.push_back(ishdCurr);

		setSectionName(uiSecnr, strName);
		setSizeOfRawData(uiSecnr, alignOffset(dwSize, getFileAlignment()));
		setPointerToRawData(uiSecnr, dwOffset);
		setVirtualSize(uiSecnr, alignOffset(dwSize, getSectionAlignment()));
		setVirtualAddress(uiSecnr, dwRva);
		setCharacteristics(uiSecnr, PELIB_IMAGE_SCN_MEM_WRITE | PELIB_IMAGE_SCN_MEM_READ | PELIB_IMAGE_SCN_CNT_INITIALIZED_DATA | PELIB_IMAGE_SCN_CNT_CODE);

		return ERROR_NONE;
	}

	/**
	* Splits an existing section in the file on the two sections. Section can only be split on the multiple
	* of section alignment. First of the new sections will inherit all the characteristics from the old section.
	* Second section will be initialized with IMAGE_SCN_MEM_WRITE | IMAGE_SCN_MEM_READ | IMAGE_SCN_CNT_INITIALIZED_DATA
	* | IMAGE_SCN_CNT_CODE. Virtual size will be modified on both sections to match the raw size in the file.
	* @param uiSectionnr The index of the section to be split.
	* @param first The name of the first of the newly created sections.
	* @param second The name of the second of the newly created sections.
	* @param dwSplitOffset File offset at which to split the section into two.
	* @todo Add option to split any section without restrictions.
	**/
	template<int x>
	int PeHeaderT<x>::splitSection(word uiSectionnr, const std::string& first, const std::string& second, dword dwSplitOffset)
	{
		if (!getFileAlignment())
		{
			return ERROR_NO_FILE_ALIGNMENT;
		}
		else if (!getSectionAlignment())
		{
			return ERROR_NO_SECTION_ALIGNMENT;
		}

		// Index needs to be in the range <0, NUMBER OF SECTIONS)
		if (uiSectionnr > calcNumberOfSections())
			return ERROR_ENTRY_NOT_FOUND;

		// Offset at which the section is going to be split must be multiple of section alignment
		if (dwSplitOffset & (getSectionAlignment() - 1))
			return ERROR_NOT_ENOUGH_SPACE;

		// Do not allow to split if the offset of split is greater than the size of the section
		// Nor do allow the section with size 0 to be created
		if (dwSplitOffset >= getVirtualSize(uiSectionnr))
			return ERROR_NOT_ENOUGH_SPACE;

		// Move every section located after the inserted section by one position
		m_vIsh.resize(m_vIsh.size() + 1);
		for (int i = calcNumberOfSections() - 2; i >= uiSectionnr + 1; --i)
			m_vIsh[i + 1] = m_vIsh[i];

		dword originalSize = getSizeOfRawData(uiSectionnr);

		// Setup the first of the new sections
		setSectionName(uiSectionnr, first);
		setSizeOfRawData(uiSectionnr, dwSplitOffset);
		setVirtualSize(uiSectionnr, dwSplitOffset);

		// Setup the second of the new sections
		setSectionName(uiSectionnr + 1, second);
		setPointerToRawData(uiSectionnr + 1, getPointerToRawData(uiSectionnr) + dwSplitOffset);
		setSizeOfRawData(uiSectionnr + 1, originalSize - dwSplitOffset);
		setVirtualAddress(uiSectionnr + 1, getVirtualAddress(uiSectionnr) + dwSplitOffset);
		setVirtualSize(uiSectionnr + 1, originalSize - dwSplitOffset);
		setCharacteristics(uiSectionnr + 1, PELIB_IMAGE_SCN_MEM_WRITE | PELIB_IMAGE_SCN_MEM_READ | PELIB_IMAGE_SCN_CNT_INITIALIZED_DATA | PELIB_IMAGE_SCN_CNT_CODE);

		return ERROR_NONE;
	}

	/**
	* Removes the section from the file. All further sections will be moved in the file to fill
	* the gap. Everything other remains untouched.
	* @param uiSectionnr The index of the section to remove.
	**/
	template<int x>
	int PeHeaderT<x>::removeSection(word uiSectionnr)
	{
		if (uiSectionnr >= calcNumberOfSections())
			return ERROR_ENTRY_NOT_FOUND;

		dword rawDiff = getSizeOfRawData(uiSectionnr);
		dword virtualDiff = getVirtualSize(uiSectionnr);
		for (int i = uiSectionnr + 1; i < calcNumberOfSections(); ++i)
		{
			setPointerToRawData(i, getPointerToRawData(i) - rawDiff);
			setVirtualAddress(i, getVirtualAddress(i) - virtualDiff);
		}

		m_vIsh.erase(m_vIsh.begin() + uiSectionnr);
		return ERROR_NONE;
	}

	/**
	* Calculates a valid SizeOfImage value given the information from the current PE header.
	* Note that this calculation works in Win2K but probably does not work in Win9X. I didn't test that though.
	* @return Valid SizeOfImage value.
	**/
	template<int x>
	unsigned int PeHeaderT<x>::calcSizeOfImage() const
	{
		// Major note here: It's possible for sections to exist with a Virtual Size of 0.
		//					That's why it's necessary to use std::max(Vsize, RawSize) here.
		//                  An example for such a file is dbeng6.exe (made by Sybase).
		//                  In this file each and every section has a VSize of 0 but it still runs.

		auto ishLastSection = std::max_element(
				m_vIsh.begin(),
				m_vIsh.end(),
				[](const auto& i1, const auto& i2) { return i1.biggerVirtualAddress(i2); }
		);

		if (ishLastSection->VirtualSize != 0) return ishLastSection->VirtualAddress + ishLastSection->VirtualSize;
		return ishLastSection->VirtualAddress + std::max(ishLastSection->VirtualSize, ishLastSection->SizeOfRawData);
	}

	/**
	* Calculates the space between the last byte of the header and the first byte that's used for something
	* else (that's either the first section or an image directory).
	* @return Unused space after the header.
	* \todo There are PE files with sections beginning at offset 0. They
	* need to be considered.
	**/
	template<int x>
	unsigned int PeHeaderT<x>::calcSpaceAfterHeader() const
	{
		return (calcStartOfCode() > size() + m_uiOffset) ? calcStartOfCode() - (size() + m_uiOffset) : 0;
	}

	/**
	* Returns the first offset of the file that's actually used for something different than the header.
	* That something is not necessarily code, it can be a data directory too.
	* This offset can be the beginning of a section or the beginning of a directory.
	* \todo Some optimizization is surely possible here.
	* \todo There are PE files with sections beginning at offset 0. They
	* need to be considered. Returning 0 for these files doesn't really make sense.
	* So far these sections are disregarded.
	**/
	template<int x>
	unsigned int PeHeaderT<x>::calcStartOfCode() const
	{
		unsigned int directories = calcNumberOfRvaAndSizes();
		VAR4_8 dwMinOffset = 0xFFFFFFFF;
		if (directories >= 1 && getIddExportRva() && rvaToOffset(getIddExportRva()) < dwMinOffset) dwMinOffset = rvaToOffset(getIddExportRva());
		if (directories >= 2 && getIddImportRva() && rvaToOffset(getIddImportRva()) < dwMinOffset) dwMinOffset = rvaToOffset(getIddImportRva());
		if (directories >= 3 && getIddResourceRva() && rvaToOffset(getIddResourceRva()) < dwMinOffset) dwMinOffset = rvaToOffset(getIddResourceRva());
		if (directories >= 4 && getIddExceptionRva()  && rvaToOffset(getIddExceptionRva()) < dwMinOffset) dwMinOffset = rvaToOffset(getIddExceptionRva());
		if (directories >= 5 && getIddSecurityRva()  && rvaToOffset(getIddSecurityRva()) < dwMinOffset) dwMinOffset = rvaToOffset(getIddSecurityRva());
		if (directories >= 6 && getIddBaseRelocRva()  && rvaToOffset(getIddBaseRelocRva()) < dwMinOffset) dwMinOffset = rvaToOffset(getIddBaseRelocRva());
		if (directories >= 7 && getIddDebugRva()  && rvaToOffset(getIddDebugRva()) < dwMinOffset) dwMinOffset = rvaToOffset(getIddDebugRva());
		if (directories >= 8 && getIddArchitectureRva()  && rvaToOffset(getIddArchitectureRva()) < dwMinOffset) dwMinOffset = rvaToOffset(getIddArchitectureRva());
		if (directories >= 9 && getIddGlobalPtrRva()  && rvaToOffset(getIddGlobalPtrRva()) < dwMinOffset) dwMinOffset = rvaToOffset(getIddGlobalPtrRva());
		if (directories >= 10 && getIddTlsRva()  && rvaToOffset(getIddTlsRva()) < dwMinOffset) dwMinOffset = rvaToOffset(getIddTlsRva());
		if (directories >= 11 && getIddLoadConfigRva()  && rvaToOffset(getIddLoadConfigRva()) < dwMinOffset) dwMinOffset = rvaToOffset(getIddLoadConfigRva());
		if (directories >= 12 && getIddBoundImportRva()  && rvaToOffset(getIddBoundImportRva()) < dwMinOffset) dwMinOffset = rvaToOffset(getIddBoundImportRva());
		if (directories >= 13 && getIddIatRva()  && rvaToOffset(getIddIatRva()) < dwMinOffset) dwMinOffset = rvaToOffset(getIddIatRva());
		if (directories >= 14 && getIddDelayImportRva()  && rvaToOffset(getIddDelayImportRva()) < dwMinOffset) dwMinOffset = rvaToOffset(getIddDelayImportRva());
		if (directories >= 15 && getIddComHeaderRva()  && rvaToOffset(getIddComHeaderRva()) < dwMinOffset) dwMinOffset = rvaToOffset(getIddComHeaderRva());

		for (word i=0;i<calcNumberOfSections();i++)
		{
			if ((getPointerToRawData(i) < dwMinOffset || dwMinOffset == 0xFFFFFFFF) && getSizeOfRawData(i))
			{
				if (getPointerToRawData(i)) dwMinOffset = getPointerToRawData(i);
			}
		}
		return (unsigned int)dwMinOffset;
	}

	/**
	* Calculates the file offset for a new section. The file offset will already be aligned to the file's FileAlignment.
	* @return Aligned file offset.
	* \todo uiSize isn't used yet. Will be used later on to search for caves.
	**/
	template<int x>
	unsigned int PeHeaderT<x>::calcOffset(/*unsigned int uiSize*/) const
	{
		unsigned int maxoffset = size();

		for (word i=0;i<calcNumberOfSections();i++)
		{
			if (getPointerToRawData(i) + getSizeOfRawData(i) > maxoffset) maxoffset = getPointerToRawData(i) + getSizeOfRawData(i);
		}

		return alignOffset(maxoffset, getFileAlignment());
	}

	/**
	* Calculates the Rva for a new section. The Rva will already be aligned to the file's SectionAlignment.
	* \todo uiSize isn't used yet. Will be used later on to search for caves.
	* @return Aligned Rva.
	**/
	template<int x>
	unsigned int PeHeaderT<x>::calcRva(/*unsigned int uiSize*/) const
	{
		// Major note here: It's possible for sections to exist with a Virtual Size of 0.
		//                  That's why it's necessary to use std::max(Vsize, RawSize) here.
		//                  An example for such a file is dbeng6.exe (made by Sybase).
		//                  In this file each and every section has a VSize of 0 but it still runs.

		unsigned int maxoffset = size();
		for (word i=0;i<calcNumberOfSections();i++)
		{
			if (getVirtualAddress(i) + std::max(getVirtualSize(i), getSizeOfRawData(i)) > maxoffset) maxoffset = getVirtualAddress(i) + std::max(getVirtualSize(i), getSizeOfRawData(i));
		}

		return alignOffset(maxoffset, getSectionAlignment());
	}

	/**
	* Returns the number of currently defined sections. Note that this value can be different from the number
	* of sections according to the header (see #PeLib::PeHeaderT<x>::getNumberOfSections).
	* @return Number of currently defined sections.
	**/
	template<int x>
	word PeHeaderT<x>::calcNumberOfSections() const
	{
		return static_cast<PeLib::word>(m_vIsh.size());
	}

	/**
	* Enlarges the physically last section in the file.
	* @param uiSize Additional size that's added to the section's size.
	**/
	template<int x>
	void PeHeaderT<x>::enlargeLastSection(unsigned int uiSize)
	{
		auto ishLastSection = std::max_element(
				m_vIsh.begin(),
				m_vIsh.end(),
				[](const auto& i1, const auto& i2) { return i1.biggerFileOffset(i2); }
		);
		unsigned int uiRawDataSize = alignOffset(ishLastSection->SizeOfRawData + uiSize, getFileAlignment());

		ishLastSection->SizeOfRawData = uiRawDataSize;
		ishLastSection->VirtualSize = ishLastSection->SizeOfRawData;

		setSizeOfImage(calcSizeOfImage());
	}

	/**
	* Determines the section which contains the file offset.
	* @param dwOffset File offset.
	* @return Section Id of the section which contains the offset.
	**/
	template<int x>
	word PeHeaderT<x>::getSectionWithOffset(VAR4_8 dwOffset) const
	{
		// Offset = 0 must be handled explicitly as there are files
		// with sections that begin at offset 0, that means the section
		// only exists in memory.

		if (!dwOffset) return std::numeric_limits<word>::max();

		for (word i=0;i<calcNumberOfSections();i++)
		{
			// Explicity exclude sections with raw pointer = 0.
			dword rawptr = getPointerToRawData(i);
			if (rawptr && rawptr <= dwOffset && rawptr + getSizeOfRawData(i) > dwOffset) return i;
		}

		return std::numeric_limits<word>::max();
	}

	/**
	* Determines the section which contains the Rva.
	* @param dwRva A relative virtual address.
	* @return Section Id of the section which contains the Rva.
	**/
	template<int x>
	word PeHeaderT<x>::getSectionWithRva(VAR4_8 dwRva) const
	{
		// Major note here: It's possible for sections to exist with a Virtual Size of 0.
		//                  That's why it's necessary to use std::max(Vsize, RawSize) here.
		//                  An example for such a file is dbeng6.exe (made by Sybase).
		//                  In this file each and every section has a VSize of 0 but it still runs.

		word actIndex = 0;
		bool detected = false;

		for (word i=0;i<calcNumberOfSections();i++)
		{
			// Weird VC++7 error doesn't allow me to use std::max here.
			dword max = getVirtualSize(i) >= getSizeOfRawData(i) ? getVirtualSize(i) : getSizeOfRawData(i);
			if (getVirtualAddress(i) <= dwRva && getVirtualAddress(i) + max > dwRva)
			{
				dword actMax = getVirtualSize(actIndex) >= getSizeOfRawData(actIndex) ? getVirtualSize(actIndex) : getSizeOfRawData(actIndex);
				if (!detected || (getVirtualAddress(i) > getVirtualAddress(actIndex) || (getVirtualAddress(i) == getVirtualAddress(actIndex) && max < actMax)))
				{
					actIndex = i;
					detected = true;
				}
			}
		}

		return detected ? actIndex : - 1;
	}

	/**
	* Corrects all faulty values of the current PE header. The following values will be corrected: NtSignature,
	* NumberOfSections, SizeOfOptionalHeader, FileAlignment (will be aligned to n*0x200),
	* SectionAlignment (will be aligned to n*0x1000), NumberOfRvaAndSizes, SizeOfHeaders, SizeOfImage,
	* Magic, Characteristics.
	* @param dwOffset Beginning of PeHeader (see #PeLib::MzHeader::getAddressOfPeHeader).
	* \todo 32bit and 64bit versions.
	**/
	template<int x>
	void PeHeaderT<x>::makeValid(dword dwOffset)
	{
		setNtSignature(PELIB_IMAGE_NT_SIGNATURE); // 'PE'
		setNumberOfSections(calcNumberOfSections());
		setSizeOfOptionalHeader(PELIB_IMAGE_OPTIONAL_HEADER<x>::size() + calcNumberOfRvaAndSizes() * 8);

		if (getCharacteristics() == 0)
			setCharacteristics(PELIB_IMAGE_FILE_EXECUTABLE_IMAGE | PELIB_IMAGE_FILE_32BIT_MACHINE);

		// 32 bits
		if (x == 32)
		{
			setMachine(PELIB_IMAGE_FILE_MACHINE_I386);
			setMagic(PELIB_IMAGE_NT_OPTIONAL_HDR32_MAGIC);
		}
		// 64 bits
		else if (x == 64)
		{
			setMachine(PELIB_IMAGE_FILE_MACHINE_AMD64);
			setMagic(PELIB_IMAGE_NT_OPTIONAL_HDR64_MAGIC);
		}

		// setImageBase(0x01000000);

		// Align file and section alignment values
		unsigned int dwAlignedOffset = alignOffset(getSectionAlignment(), 0x1000);
		setSectionAlignment(dwAlignedOffset ? dwAlignedOffset : 0x1000);

		dwAlignedOffset = alignOffset(getFileAlignment(), 0x200);
		setFileAlignment(dwAlignedOffset ? dwAlignedOffset : 0x200);

//		setMajorSubsystemVersion(4);
//		setSubsystem(IMAGE_SUBSYSTEM_WINDOWS_GUI);
		m_inthHeader.dataDirectories.resize(getNumberOfRvaAndSizes());

		// Code below depends on code above. Don't change the order.
		dword dwSizeOfHeaders = alignOffset(dwOffset + size(), getFileAlignment());
		setSizeOfHeaders(dwSizeOfHeaders);

		dword dwSizeOfImage = alignOffset(dwSizeOfHeaders, getSectionAlignment());

		dword dwOffsetDiff = dwSizeOfHeaders - getPointerToRawData(0);
		for (int i=0;i<calcNumberOfSections();i++)
		{
			dwSizeOfImage += alignOffset(getVirtualSize(i), getSectionAlignment());

			// If the size of headers changed, we need to move all section data further
			if (dwOffsetDiff)
				setPointerToRawData(i, getPointerToRawData(i) + dwOffsetDiff);
		}

		dwSizeOfImage = alignOffset(dwSizeOfImage, getSectionAlignment());
		setSizeOfImage(dwSizeOfImage);
	}

	template<int x>
	unsigned int PeHeaderT<x>::offsetToRva(VAR4_8 dwOffset) const
	{
		if (dwOffset < calcStartOfCode()) return dwOffset;

		PeLib::word uiSecnr = getSectionWithOffset(dwOffset);

		if (uiSecnr == 0xFFFF) return (unsigned int)-1;

		return getVirtualAddress(uiSecnr) + dwOffset - getPointerToRawData(uiSecnr);
	}

	/**
	* Converts a file offset to a virtual address.
	* @param dwOffset File offset.
	* @return Virtual Address.
	**/
	template<int x>
	unsigned int PeHeaderT<x>::offsetToVa(VAR4_8 dwOffset) const
	{
		if (dwOffset < calcStartOfCode()) return getImageBase() + dwOffset;

		PeLib::word uiSecnr = getSectionWithOffset(dwOffset);

		if (uiSecnr == 0xFFFF) return -1;

		return getImageBase() + getVirtualAddress(uiSecnr) + dwOffset - getPointerToRawData(uiSecnr);
	}

	template<int x>
	void PeHeaderT<x>::readHeader(InputBuffer& ibBuffer, PELIB_IMAGE_NT_HEADERS<x>& header)
	{
		ibBuffer >> header.Signature;

		ibBuffer >> header.FileHeader.Machine;
		ibBuffer >> header.FileHeader.NumberOfSections;
		ibBuffer >> header.FileHeader.TimeDateStamp;
		ibBuffer >> header.FileHeader.PointerToSymbolTable;
		ibBuffer >> header.FileHeader.NumberOfSymbols;
		ibBuffer >> header.FileHeader.SizeOfOptionalHeader;
		ibBuffer >> header.FileHeader.Characteristics;
		ibBuffer >> header.OptionalHeader.Magic;

		ibBuffer >> header.OptionalHeader.MajorLinkerVersion;
		ibBuffer >> header.OptionalHeader.MinorLinkerVersion;
		ibBuffer >> header.OptionalHeader.SizeOfCode;
		ibBuffer >> header.OptionalHeader.SizeOfInitializedData;
		ibBuffer >> header.OptionalHeader.SizeOfUninitializedData;
		ibBuffer >> header.OptionalHeader.AddressOfEntryPoint;
		ibBuffer >> header.OptionalHeader.BaseOfCode;
		readBaseOfData(ibBuffer, header);
		ibBuffer >> header.OptionalHeader.ImageBase;
		ibBuffer >> header.OptionalHeader.SectionAlignment;
		ibBuffer >> header.OptionalHeader.FileAlignment;
		ibBuffer >> header.OptionalHeader.MajorOperatingSystemVersion;
		ibBuffer >> header.OptionalHeader.MinorOperatingSystemVersion;
		ibBuffer >> header.OptionalHeader.MajorImageVersion;
		ibBuffer >> header.OptionalHeader.MinorImageVersion;
		ibBuffer >> header.OptionalHeader.MajorSubsystemVersion;
		ibBuffer >> header.OptionalHeader.MinorSubsystemVersion;
		ibBuffer >> header.OptionalHeader.Win32VersionValue;
		ibBuffer >> header.OptionalHeader.SizeOfImage;
		ibBuffer >> header.OptionalHeader.SizeOfHeaders;
		m_checksumFileOffset = m_uiOffset + ibBuffer.get();
		ibBuffer >> header.OptionalHeader.CheckSum;
		ibBuffer >> header.OptionalHeader.Subsystem;
		ibBuffer >> header.OptionalHeader.DllCharacteristics;
		ibBuffer >> header.OptionalHeader.SizeOfStackReserve;
		ibBuffer >> header.OptionalHeader.SizeOfStackCommit;
		ibBuffer >> header.OptionalHeader.SizeOfHeapReserve;
		ibBuffer >> header.OptionalHeader.SizeOfHeapCommit;
		ibBuffer >> header.OptionalHeader.LoaderFlags;
		ibBuffer >> header.OptionalHeader.NumberOfRvaAndSizes;
	}

	template<int x>
	void PeHeaderT<x>::readDataDirectories(
			std::istream& inStream,
			unsigned int uiOffset,
			PELIB_IMAGE_NT_HEADERS<x>& header)
	{
		IStreamWrapper inStream_w(inStream);

		std::uint64_t ulFileSize = fileSize(inStream_w);
		inStream_w.seekg(uiOffset, std::ios::beg);

		std::vector<unsigned char> iddBuffer(PELIB_IMAGE_DATA_DIRECTORY::size());
		PELIB_IMAGE_DATA_DIRECTORY idd;

		// There is no more than 16 directories in header, even though PE header declares more.
		unsigned int uiNumberOfDirectories = std::min(header.OptionalHeader.NumberOfRvaAndSizes, 16u);

		for (unsigned int i = 0; i < uiNumberOfDirectories; i++)
		{
			if (uiOffset >= ulFileSize)
			{
				break;
			}

			auto incomplete = false;
			if (uiOffset + PELIB_IMAGE_DATA_DIRECTORY::size() > ulFileSize)
			{
				if (uiOffset + sizeof(idd.VirtualAddress) <= ulFileSize)
				{
					incomplete = true;
				}
				else
				{
					break;
				}
			}

			if (i == PELIB_IMAGE_DIRECTORY_ENTRY_SECURITY)
				m_secDirFileOffset = (unsigned long)inStream_w.tellg();

			iddBuffer.resize(PELIB_IMAGE_DATA_DIRECTORY::size());
			inStream_w.read(reinterpret_cast<char*>(iddBuffer.data()), iddBuffer.size());

			InputBuffer ibBuffer(iddBuffer);
			ibBuffer >> idd.VirtualAddress;
			ibBuffer >> idd.Size;
			header.lastDirectoryIsIncomplete = incomplete;

			header.dataDirectories.push_back(idd);

			uiOffset += PELIB_IMAGE_DATA_DIRECTORY::size();
		}
	}

	template<int x>
	std::vector<PELIB_IMAGE_SECTION_HEADER> PeHeaderT<x>::readSections(
			std::istream& inStream,
			unsigned int uiOffset,
			PELIB_IMAGE_NT_HEADERS<x>& header)
	{
		IStreamWrapper inStream_w(inStream);

		const unsigned long long stringTableOffset = header.FileHeader.PointerToSymbolTable + header.FileHeader.NumberOfSymbols * PELIB_IMAGE_SIZEOF_COFF_SYMBOL;
		std::vector<PELIB_IMAGE_SECTION_HEADER> vIshdCurr;
		bool bRawDataBeyondEOF = false;

		std::vector<unsigned char> ishBuffer(PELIB_IMAGE_SECTION_HEADER::size());
		PELIB_IMAGE_SECTION_HEADER ishCurr;
		std::uint64_t ulFileSize = fileSize(inStream_w);

		// Check overflow of the section headers
		std::uint32_t SectionHdrOffset = MzHeader().e_lfanew + sizeof(std::uint32_t) + header.FileHeader.size() + header.FileHeader.SizeOfOptionalHeader;
		if(SectionHdrOffset > (std::uint32_t)ulFileSize)
			setLoaderError(LDR_ERROR_SECTION_HEADERS_OUT_OF_IMAGE);

		for (unsigned int i = 0; i < header.FileHeader.NumberOfSections; i++)
		{
			if (uiOffset + PELIB_IMAGE_SECTION_HEADER::size() > ulFileSize)
				break;

			// Clear error bits, because reading from symbol table might have failed.
			inStream_w.clear();
			inStream_w.seekg(uiOffset, std::ios::beg);
			inStream_w.read(reinterpret_cast<char*>(ishBuffer.data()), ishBuffer.size());
			InputBuffer ibBuffer(ishBuffer);

			ibBuffer.read(reinterpret_cast<char*>(ishCurr.Name), 8);
			// get name from string table
			if (ishCurr.Name[0] == '/')
			{
				unsigned long long stringTableIndex = 0;

				for (unsigned long long j = 1; j < 8 && isdigit(static_cast<unsigned char>(ishCurr.Name[j])); ++j)
				{
					stringTableIndex *= 10;
					stringTableIndex += ishCurr.Name[j] - '0';
				}

				if (stringTableOffset + stringTableIndex <= ulFileSize)
				{
					getStringFromFileOffset(
							inStream_w,
							ishCurr.StringTableName,
							(std::size_t)(stringTableOffset + stringTableIndex),
							PELIB_IMAGE_SIZEOF_MAX_NAME,
							true,
							true);
				}
			}
			else
			{
				ishCurr.StringTableName.clear();
			}
			ibBuffer >> ishCurr.VirtualSize;
			ibBuffer >> ishCurr.VirtualAddress;
			ibBuffer >> ishCurr.SizeOfRawData;
			ibBuffer >> ishCurr.PointerToRawData;
			ibBuffer >> ishCurr.PointerToRelocations;
			ibBuffer >> ishCurr.PointerToLinenumbers;
			ibBuffer >> ishCurr.NumberOfRelocations;
			ibBuffer >> ishCurr.NumberOfLinenumbers;
			ibBuffer >> ishCurr.Characteristics;
			vIshdCurr.push_back(ishCurr);

			uiOffset += PELIB_IMAGE_SECTION_HEADER::size();
		}

		// Verify section headers
		std::uint64_t NextVirtualAddress = header.OptionalHeader.ImageBase;
		std::uint32_t NumberOfSectionPTEs = AlignToSize(header.OptionalHeader.SizeOfHeaders, header.OptionalHeader.SectionAlignment) / PELIB_PAGE_SIZE;
		std::uint32_t NumberOfPTEs = BytesToPages(header.OptionalHeader.SizeOfImage);
		std::uint32_t FileAlignmentMask = header.OptionalHeader.FileAlignment - 1;
		bool SingleSubsection = (header.OptionalHeader.SectionAlignment < PELIB_PAGE_SIZE);

		// Verify the image
		if (!SingleSubsection)
		{
			// Some extra checks done by the loader
			if ((header.OptionalHeader.SizeOfHeaders + (header.OptionalHeader.SectionAlignment - 1)) < header.OptionalHeader.SizeOfHeaders)
				setLoaderError(LDR_ERROR_SECTION_HEADERS_OVERFLOW);

			if (NumberOfSectionPTEs > NumberOfPTEs)
				setLoaderError(LDR_ERROR_SIZE_OF_HEADERS_INVALID);

			// Update the virtual address
			NextVirtualAddress += NumberOfSectionPTEs * PELIB_PAGE_SIZE;
			NumberOfPTEs -= NumberOfSectionPTEs;
		}
		else
		{
			NumberOfSectionPTEs = AlignToSize(header.OptionalHeader.SizeOfImage, PELIB_PAGE_SIZE) / PELIB_PAGE_SIZE;
			NumberOfPTEs -= NumberOfSectionPTEs;
		}

		for (auto sectHdr : vIshdCurr)
		{
			std::uint32_t PointerToRawData = (sectHdr.SizeOfRawData != 0) ? sectHdr.PointerToRawData : 0;
			std::uint32_t EndOfRawData = PointerToRawData + sectHdr.SizeOfRawData;
			std::uint32_t VirtualSize = (sectHdr.VirtualSize != 0) ? sectHdr.VirtualSize : sectHdr.SizeOfRawData;

			// Overflow check
			if ((PointerToRawData + sectHdr.SizeOfRawData) < PointerToRawData)
				setLoaderError(LDR_ERROR_RAW_DATA_OVERFLOW);

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
				if (NextVirtualAddress != header.OptionalHeader.ImageBase + sectHdr.VirtualAddress)
				{
					setLoaderError(LDR_ERROR_INVALID_SECTION_VA);
				}

				// Check section size
				if ((VirtualSize + (PELIB_PAGE_SIZE - 1)) <= VirtualSize)
				{
					setLoaderError(LDR_ERROR_INVALID_SECTION_VSIZE);
				}

				// Calculate number of PTEs in the section
				NumberOfSectionPTEs = AlignToSize(VirtualSize, header.OptionalHeader.SectionAlignment) / PELIB_PAGE_SIZE;
				if (NumberOfSectionPTEs > NumberOfPTEs)
				{
					setLoaderError(LDR_ERROR_INVALID_SECTION_VSIZE);
				}

				NumberOfPTEs -= NumberOfSectionPTEs;

				// Check end of the raw data for the section
				if (((PointerToRawData + sectHdr.SizeOfRawData + FileAlignmentMask) & ~FileAlignmentMask) < PointerToRawData)
				{
					setLoaderError(LDR_ERROR_INVALID_SECTION_RAWSIZE);
				}

				NextVirtualAddress += NumberOfSectionPTEs * PELIB_PAGE_SIZE;
			}

			// Check for raw data beyond end-of-file
			// Note that Windows loader doesn't check this on files that are mapped as single section.
			// We will do that nontheless, because we want to know that a file is cut.
			if (PointerToRawData != 0 && EndOfRawData > (std::uint32_t)ulFileSize)
				bRawDataBeyondEOF = true;
		}

		// Verify the image size
		std::uint32_t ThresholdNumberOfPTEs = (SingleSubsection == false) ? (header.OptionalHeader.SectionAlignment / PELIB_PAGE_SIZE) : 1;
		if (NumberOfPTEs >= ThresholdNumberOfPTEs)
		{
			setLoaderError(LDR_ERROR_INVALID_SIZE_OF_IMAGE);
		}

		// Did we detect a trimmed file?
		if (bRawDataBeyondEOF)
		{
			bool bFileLoadable = false;

			// Special exception: Even if cut, the file is still loadable
			// if the last section is in the file range. This is because
			// the PE loader in Windows only cares about whether the last section is in the file range
			if (!vIshdCurr.empty())
			{
				PELIB_IMAGE_SECTION_HEADER & lastSection = vIshdCurr.back();
				std::uint32_t PointerToRawData = (lastSection.SizeOfRawData != 0) ? lastSection.PointerToRawData : 0;
				std::uint32_t EndOfRawData = PointerToRawData + lastSection.SizeOfRawData;

				if ((lastSection.SizeOfRawData == 0) || (EndOfRawData <= (std::uint32_t)ulFileSize))
				{
					setLoaderError(LDR_ERROR_FILE_IS_CUT_LOADABLE);
					bFileLoadable = true;
				}
			}

			// If the file is not loadable, set the "file is cut" error
			if (bFileLoadable == false)
			{
				setLoaderError(LDR_ERROR_FILE_IS_CUT);
			}
		}
		return vIshdCurr;
	}

	template<int x>
	LoaderError PeHeaderT<x>::loaderError() const
	{
		return m_ldrError;
	}

	template<int x>
	void PeHeaderT<x>::setLoaderError(LoaderError ldrError)
	{
		// Do not override an existing loader error
		if (m_ldrError == LDR_ERROR_NONE)
		{
			m_ldrError = ldrError;
		}
	}

	/**
	* Reads the PE header from a file Note that this function does not verify if a file is actually a MZ file.
	* For this purpose see #PeLib::PeHeaderT<x>::isValid. The only check this function makes is a check to see if
	* the file is large enough to be a PE header. If the data is valid doesn't matter.
	* @param inStream Input stream.
	* @param uiOffset File offset of PE header (see #PeLib::MzHeader::getAddressOfPeHeader).
	* @param mzHeader Reference to MZ header.
	**/
	template<int x>
	int PeHeaderT<x>::read(
			std::istream& inStream,
			unsigned int ntHeaderOffset,
			const MzHeader &mzHeader)
	{
		IStreamWrapper inStream_w(inStream);

		m_mzHeader = mzHeader;
		m_uiOffset = ntHeaderOffset;
		PELIB_IMAGE_NT_HEADERS<x> header;

		if (!inStream_w)
		{
			return ERROR_OPENING_FILE;
		}

		// Check the position of the NT header for integer overflow
		if (ntHeaderOffset + header.size() < ntHeaderOffset)
			setLoaderError(LDR_ERROR_NTHEADER_OFFSET_OVERFLOW);
		if((std::uint64_t)ntHeaderOffset + header.size() > fileSize(inStream_w))
			setLoaderError(LDR_ERROR_NTHEADER_OUT_OF_FILE);

		std::vector<unsigned char> vBuffer(header.size());

		inStream_w.seekg(ntHeaderOffset, std::ios::beg);
		inStream_w.read(reinterpret_cast<char*>(vBuffer.data()), static_cast<std::streamsize>(vBuffer.size()));

		InputBuffer ibBuffer(vBuffer);

		readHeader(ibBuffer, header);

		// Verify the NT signature
		if (header.Signature != PeLib::PELIB_IMAGE_NT_SIGNATURE)
			setLoaderError(LDR_ERROR_NO_NT_SIGNATURE);

		// 7baebc6d9f2185fafa760c875ab1386f385a0b3fecf2e6ae339abb4d9ac58f3e
		if (header.FileHeader.Machine == 0 && header.FileHeader.SizeOfOptionalHeader == 0)
			setLoaderError(LDR_ERROR_FILE_HEADER_INVALID);

		if (!(header.FileHeader.Characteristics & PeLib::PELIB_IMAGE_FILE_EXECUTABLE_IMAGE))
			setLoaderError(LDR_ERROR_IMAGE_NON_EXECUTABLE);
		if (header.OptionalHeader.Magic != PeLib::PELIB_IMAGE_NT_OPTIONAL_HDR32_MAGIC &&
			header.OptionalHeader.Magic != PeLib::PELIB_IMAGE_NT_OPTIONAL_HDR64_MAGIC)
			setLoaderError(LDR_ERROR_NO_OPTHDR_MAGIC);

		// SizeOfHeaders must be nonzero if not a single subsection
		if(header.OptionalHeader.SectionAlignment >= PELIB_PAGE_SIZE && header.OptionalHeader.SizeOfHeaders == 0)
			setLoaderError(LDR_ERROR_SIZE_OF_HEADERS_ZERO);

		// File alignment must not be 0
		if(header.OptionalHeader.FileAlignment == 0)
			setLoaderError(LDR_ERROR_FILE_ALIGNMENT_ZERO);

		// File alignment must be a power of 2
		if(header.OptionalHeader.FileAlignment & (header.OptionalHeader.FileAlignment-1))
			setLoaderError(LDR_ERROR_FILE_ALIGNMENT_NOT_POW2);

		// Section alignment must not be 0
		if (header.OptionalHeader.SectionAlignment == 0)
			setLoaderError(LDR_ERROR_SECTION_ALIGNMENT_ZERO);

		// Section alignment must be a power of 2
		if (header.OptionalHeader.SectionAlignment & (header.OptionalHeader.SectionAlignment - 1))
			setLoaderError(LDR_ERROR_SECTION_ALIGNMENT_NOT_POW2);

		if (header.OptionalHeader.SectionAlignment < header.OptionalHeader.FileAlignment)
			setLoaderError(LDR_ERROR_SECTION_ALIGNMENT_TOO_SMALL);

		// Check for images with "super-section": FileAlignment must be equal to SectionAlignment
		if ((header.OptionalHeader.FileAlignment & 511) && (header.OptionalHeader.SectionAlignment != header.OptionalHeader.FileAlignment))
			setLoaderError(LDR_ERROR_SECTION_ALIGNMENT_INVALID);

		// Check for largest image
		if(header.OptionalHeader.SizeOfImage > PELIB_MM_SIZE_OF_LARGEST_IMAGE)
			setLoaderError(LDR_ERROR_SIZE_OF_IMAGE_TOO_BIG);

		// Check for 32-bit images
		if (header.OptionalHeader.Magic == PeLib::PELIB_IMAGE_NT_OPTIONAL_HDR32_MAGIC && header.FileHeader.Machine != PeLib::PELIB_IMAGE_FILE_MACHINE_I386)
			setLoaderError(LDR_ERROR_INVALID_MACHINE32);

		// Check for 64-bit images
		if (header.OptionalHeader.Magic == PeLib::PELIB_IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		{
			if (header.FileHeader.Machine != PeLib::PELIB_IMAGE_FILE_MACHINE_AMD64 && header.FileHeader.Machine != PeLib::PELIB_IMAGE_FILE_MACHINE_IA64)
				setLoaderError(LDR_ERROR_INVALID_MACHINE64);
		}

		// Check the size of image
		if(header.OptionalHeader.SizeOfHeaders > header.OptionalHeader.SizeOfImage)
			setLoaderError(LDR_ERROR_SIZE_OF_HEADERS_INVALID);

		// On 64-bit Windows, size of optional header must be properly aligned to 8-byte boundary
		if (header.FileHeader.SizeOfOptionalHeader & (sizeof(std::uint64_t) - 1))
			setLoaderError(LDR_ERROR_SIZE_OF_OPTHDR_NOT_ALIGNED);

		// Set the size of image
		if(BytesToPages(header.OptionalHeader.SizeOfImage) == 0)
			setLoaderError(LDR_ERROR_SIZE_OF_IMAGE_ZERO);

		// Check for proper alignment of the image base
		if(header.OptionalHeader.ImageBase & (PELIB_SIZE_64KB - 1))
			setLoaderError(LDR_ERROR_IMAGE_BASE_NOT_ALIGNED);

		// header now contains only Signature + File Header + Optional Header
		readDataDirectories(inStream_w, ntHeaderOffset + header.size(), header);

		// Section headers begin at the offset of the optional header + SizeOfOptionalHeader
		// We need to do this because section headers may be hidden in optional header
		auto secHdrOff = ntHeaderOffset
				+ header.sizeOfSignature()
				+ PELIB_IMAGE_FILE_HEADER::size()
				+ header.FileHeader.SizeOfOptionalHeader;
		m_vIsh = readSections(inStream_w, secHdrOff, header);

		std::swap(m_inthHeader, header);

		return ERROR_NONE;
	}

	/**
	* Rebuilds the PE header so that it can be written to a file. It's not guaranteed that the
	* header will be valid. If you want to make sure that the header will be valid you
	* must call #PeLib::PeHeaderT<x>::makeValid first.
	* @param vBuffer Buffer where the rebuilt header will be stored.
	**/
	template<int x>
	void PeHeaderT<x>::rebuild(std::vector<byte>& vBuffer) const
	{
		OutputBuffer obBuffer(vBuffer);

		obBuffer << m_inthHeader.Signature;

		obBuffer << m_inthHeader.FileHeader.Machine;
		obBuffer << m_inthHeader.FileHeader.NumberOfSections;
		obBuffer << m_inthHeader.FileHeader.TimeDateStamp;
		obBuffer << m_inthHeader.FileHeader.PointerToSymbolTable;
		obBuffer << m_inthHeader.FileHeader.NumberOfSymbols;
		obBuffer << m_inthHeader.FileHeader.SizeOfOptionalHeader;
		obBuffer << m_inthHeader.FileHeader.Characteristics;
		obBuffer << m_inthHeader.OptionalHeader.Magic;
		obBuffer << m_inthHeader.OptionalHeader.MajorLinkerVersion;
		obBuffer << m_inthHeader.OptionalHeader.MinorLinkerVersion;
		obBuffer << m_inthHeader.OptionalHeader.SizeOfCode;
		obBuffer << m_inthHeader.OptionalHeader.SizeOfInitializedData;
		obBuffer << m_inthHeader.OptionalHeader.SizeOfUninitializedData;
		obBuffer << m_inthHeader.OptionalHeader.AddressOfEntryPoint;
		obBuffer << m_inthHeader.OptionalHeader.BaseOfCode;
		rebuildBaseOfData(obBuffer);
//		obBuffer << m_inthHeader.OptionalHeader.BaseOfData;
		obBuffer << m_inthHeader.OptionalHeader.ImageBase;
		obBuffer << m_inthHeader.OptionalHeader.SectionAlignment;
		obBuffer << m_inthHeader.OptionalHeader.FileAlignment;
		obBuffer << m_inthHeader.OptionalHeader.MajorOperatingSystemVersion;
		obBuffer << m_inthHeader.OptionalHeader.MinorOperatingSystemVersion;
		obBuffer << m_inthHeader.OptionalHeader.MajorImageVersion;
		obBuffer << m_inthHeader.OptionalHeader.MinorImageVersion;
		obBuffer << m_inthHeader.OptionalHeader.MajorSubsystemVersion;
		obBuffer << m_inthHeader.OptionalHeader.MinorSubsystemVersion;
		obBuffer << m_inthHeader.OptionalHeader.Win32VersionValue;
		obBuffer << m_inthHeader.OptionalHeader.SizeOfImage;
		obBuffer << m_inthHeader.OptionalHeader.SizeOfHeaders;
		obBuffer << m_inthHeader.OptionalHeader.CheckSum;
		obBuffer << m_inthHeader.OptionalHeader.Subsystem;
		obBuffer << m_inthHeader.OptionalHeader.DllCharacteristics;
		obBuffer << m_inthHeader.OptionalHeader.SizeOfStackReserve;
		obBuffer << m_inthHeader.OptionalHeader.SizeOfStackCommit;
		obBuffer << m_inthHeader.OptionalHeader.SizeOfHeapReserve;
		obBuffer << m_inthHeader.OptionalHeader.SizeOfHeapCommit;
		obBuffer << m_inthHeader.OptionalHeader.LoaderFlags;
		obBuffer << m_inthHeader.OptionalHeader.NumberOfRvaAndSizes;

		// The 0x10 data directories
		for (unsigned int i=0;i<calcNumberOfRvaAndSizes();i++)
		{
			obBuffer << m_inthHeader.dataDirectories[i].VirtualAddress;
			obBuffer << m_inthHeader.dataDirectories[i].Size;
		}

		// The section definitions
		const unsigned int nrSections = calcNumberOfSections();
		for (unsigned int i=0;i<nrSections;i++)
		{
			char temp[9] = {0};
			strcpy(temp, getSectionName(i).c_str());
			obBuffer.add(temp, 8);
			obBuffer << m_vIsh[i].VirtualSize;
			obBuffer << m_vIsh[i].VirtualAddress;
			obBuffer << m_vIsh[i].SizeOfRawData;
			obBuffer << m_vIsh[i].PointerToRawData;
			obBuffer << m_vIsh[i].PointerToRelocations;
			obBuffer << m_vIsh[i].PointerToLinenumbers;
			obBuffer << m_vIsh[i].NumberOfRelocations;
			obBuffer << m_vIsh[i].NumberOfLinenumbers;
			obBuffer << m_vIsh[i].Characteristics;
		}
	}

	/**
	 * Determines the validity of given RVA. RVA has to be smaller than size of image.
	 * If RVA is smaller than file alignment, it is valid. If RVA falls into range of
	 * any section, it is valid. If the section has no virtual size, its raw size is considered.
	 * @param rva A relative virtual address.
	 * @return True if RVA is valid, otherwise false.
	 */
	template<int x>
	bool PeHeaderT<x>::isValidRva(VAR4_8 rva) const
	{
		if (rva >= getSizeOfImage())
			return false;

		// If there are no sections, the compare with size of image is sufficient.
		if (calcNumberOfSections() == 0)
			return true;

		// Everything under file alignment should be allowed.
		if (rva < getFileAlignment())
			return true;

		for (word i = 0; i < calcNumberOfSections(); ++i)
		{
			// Sample 91DE52AB3F94A6372088DD843485414BA2B3734BDF58C4DE40DF3B50B4301C57:
			// Section[0].VirtualAddress = 0x1000
			// Section[0].VirtualSize = 0x3428 (in fact 0x4000 due to section alignment)
			// Section[0].SizeOfRawData = 0x3600
			// IMAGE_IMPORT_DESCRIPTOR[0]::Name is 0x44DE, which is evaluated as invalid if alignment is not taken into account

			dword beginOfSection = getVirtualAddress(i);
			dword sizeOfSection = getVirtualSize(i);

			// Perform proper alignment on the section length
			if (sizeOfSection == 0)
				sizeOfSection = getSizeOfRawData(i);
			sizeOfSection = AlignToSize(sizeOfSection, getSectionAlignment());

			// OK if the RVA is within reach of the section
			if (beginOfSection <= rva && rva < beginOfSection + sizeOfSection)
				return true;
		}

		return false;
	}

	/**
	* Converts a relative virtual offset to a file offset.
	* @param dwRva A relative virtual offset.
	* @return A file offset.
	* \todo It's not always 0x1000.
	**/
	template<int x>
	typename FieldSizes<x>::VAR4_8 PeHeaderT<x>::rvaToOffset(VAR4_8 dwRva) const
	{
		// XXX: Not correct
		if (dwRva < 0x1000) return dwRva;

		PeLib::word uiSecnr = getSectionWithRva(dwRva);

		if (uiSecnr == 0xFFFF || dwRva > getVirtualAddress(uiSecnr) + getSizeOfRawData(uiSecnr))
		{
			return std::numeric_limits<VAR4_8>::max();
		}

		if (getPointerToRawData(uiSecnr) < getFileAlignment())
		{
			return 0 + dwRva - getVirtualAddress(uiSecnr);
		}

		return getPointerToRawData(uiSecnr) + (dwRva - getVirtualAddress(uiSecnr));
	}

	template<int x>
	typename FieldSizes<x>::VAR4_8 PeHeaderT<x>::rvaToOffsetSpeculative(VAR4_8 dwRva) const
	{
		const auto offset = rvaToOffset(dwRva);
		if (offset != std::numeric_limits<VAR4_8>::max())
		{
			return offset;
		}

		const auto uiSecnr = getSectionWithRva(dwRva);
		if (uiSecnr == 0xFFFF)
		{
			return std::numeric_limits<VAR4_8>::max();
		}

		if (getPointerToRawData(uiSecnr) < getFileAlignment())
		{
			return 0 + dwRva - getVirtualAddress(uiSecnr);
		}

		return getPointerToRawData(uiSecnr) + (dwRva - getVirtualAddress(uiSecnr));
	}

	/**
	* Converts a relative virtual offset to a virtual offset.
	* @param dwRva A relative virtual offset.
	* @return A virtual offset.
	**/
	template<int x>
	typename FieldSizes<x>::VAR4_8 PeHeaderT<x>::rvaToVa(VAR4_8 dwRva) const
	{
		return getImageBase() + dwRva;
	}

	/**
	* Calculates the size of the current PE header. This includes the actual header and the section definitions.
	* @return Size of the current PE header.
	* \todo Better handling of files with less than 0x10 directories.
	**/
	template<int x>
	unsigned int PeHeaderT<x>::size() const
	{
		return m_inthHeader.size() + getNumberOfSections() * PELIB_IMAGE_SECTION_HEADER::size();
	}

	// \todo Not sure if this works.
	template<int x>
	typename FieldSizes<x>::VAR4_8 PeHeaderT<x>::vaToRva(VAR4_8 dwRva) const
	{
		if (dwRva - getImageBase() < calcStartOfCode()) return dwRva - getImageBase();

		if (getSectionWithRva(dwRva - getImageBase()) == 0xFFFF) return -1;

		return dwRva - getImageBase();
	}

	template<int x>
	typename FieldSizes<x>::VAR4_8 PeHeaderT<x>::vaToOffset(VAR4_8 dwRva) const
	{
		return rvaToOffset(dwRva - getImageBase());
	}

	template<int x>
	typename FieldSizes<x>::VAR4_8 PeHeaderT<x>::vaToOffsetSpeculative(VAR4_8 dwRva) const
	{
		return rvaToOffsetSpeculative(dwRva - getImageBase());
	}

	/**
	* Saves the PE header to a file. Note that this only saves the header information, if you have added sections
	* and want to save these to the file you have to call #PeLib::PeHeaderT<x>::saveSections too. This function also
	* does not verify if the PE header is correct. If you want to make sure that the current PE header is valid,
	* call #PeLib::PeHeaderT<x>::isValid and #PeLib::PeHeaderT<x>::makeValid first.
	* @param strFilename Filename of the file the header will be written to.
	* @param uiOffset File offset the header will be written to.
	**/
	template<int x>
	int PeHeaderT<x>::write(std::string strFilename, unsigned int uiOffset) const
	{
		std::fstream ofFile(strFilename.c_str(), std::ios_base::in);

		if (!ofFile)
		{
			ofFile.clear();
			ofFile.open(strFilename.c_str(), std::ios_base::out | std::ios_base::binary);
		}
		else
		{
			ofFile.close();
			ofFile.open(strFilename.c_str(), std::ios_base::in | std::ios_base::out | std::ios_base::binary);
		}

		if (!ofFile)
		{
			return ERROR_OPENING_FILE;
		}

		ofFile.seekp(uiOffset, std::ios::beg);

		std::vector<unsigned char> vBuffer;

		rebuild(vBuffer);

		ofFile.write(reinterpret_cast<const char*>(vBuffer.data()), static_cast<unsigned int>(vBuffer.size()));

		ofFile.close();

		return ERROR_NONE;
	}

	/**
	* Overwrites a section's data.
	* @param wSecnr Number of the section which will be overwritten.
	* @param strFilename Name of the file where the section will be written to.
	* @param wSecnr Number of the section that will be written.
	* @param vBuffer New data of the section.
	**/
	template<int x>
	int PeHeaderT<x>::writeSectionData(const std::string& strFilename, word wSecnr, const std::vector<byte>& vBuffer) const
	{
		std::fstream ofFile(strFilename.c_str(), std::ios_base::in);

		if (!ofFile)
		{
			ofFile.clear();
			ofFile.open(strFilename.c_str(), std::ios_base::out | std::ios_base::binary);
		}
		else
		{
			ofFile.close();
			ofFile.open(strFilename.c_str(), std::ios_base::in | std::ios_base::out | std::ios_base::binary);
		}

		if (!ofFile)
		{
			ofFile.clear();

			return ERROR_OPENING_FILE;
		}

		ofFile.seekp(getPointerToRawData(wSecnr), std::ios::beg);

		ofFile.write(reinterpret_cast<const char*>(vBuffer.data()), std::min(static_cast<unsigned int>(vBuffer.size()), getSizeOfRawData(wSecnr)));

		ofFile.close();

		return ERROR_NONE;
	}

	template<int x>
	unsigned int PeHeaderT<x>::getChecksumFileOffset() const
	{
		return m_checksumFileOffset;
	}

	template<int x>
	unsigned int PeHeaderT<x>::getSecDirFileOffset() const
	{
		return m_secDirFileOffset;
	}

	template<int x>
	int PeHeaderT<x>::writeSections(const std::string& strFilename) const
	{
		std::fstream ofFile(strFilename.c_str(), std::ios_base::in);

		if (!ofFile)
		{
			ofFile.clear();
			ofFile.open(strFilename.c_str(), std::ios_base::out | std::ios_base::binary);
		}
		else
		{
			ofFile.close();
			ofFile.open(strFilename.c_str(), std::ios_base::in | std::ios_base::out | std::ios_base::binary);
		}

		if (!ofFile)
		{
			return ERROR_OPENING_FILE;
		}

		std::uint64_t ulFileSize = fileSize(ofFile);

		for (int i=0;i<calcNumberOfSections();i++)
		{
			if (ulFileSize < getPointerToRawData(i) + getSizeOfRawData(i))
			{
				unsigned int uiToWrite = getPointerToRawData(i) + getSizeOfRawData(i) - ulFileSize;
				std::vector<char> vBuffer(uiToWrite);
				ofFile.seekp(0, std::ios::end);
				ofFile.write(vBuffer.data(), static_cast<unsigned int>(vBuffer.size()));
				ulFileSize = getPointerToRawData(i) + getSizeOfRawData(i);
			}
		}

		ofFile.close();

		return ERROR_NONE;
	}

	/**
	* Returns reference to NT headers.
	* @return Reference to NT headers.
	**/
	template<int x>
	const PELIB_IMAGE_NT_HEADERS<x>& PeHeaderT<x>::getNtHeaders() const
	{
		return m_inthHeader;
	}

	/**
	* Returns the file's Nt signature.
	* @return The Nt signature value from the PE header.
	**/
	template<int x>
	dword PeHeaderT<x>::getNtSignature() const
	{
		return m_inthHeader.Signature;
	}

	/**
	* Returns the file's machine.
	* @return The Machine value from the PE header.
	**/
	template<int x>
	word PeHeaderT<x>::getMachine() const
	{
		return m_inthHeader.FileHeader.Machine;
	}

	/**
	* Returns the file's number of sections as defined in the header. Note that this value can be different
	* from the number of defined sections (#see PeLib::PeHeaderT<x>::getNumberOfSections).
	* @return The NumberOfSections value from the PE header.
	**/
	template<int x>
	word PeHeaderT<x>::getNumberOfSections() const
	{
		return m_inthHeader.FileHeader.NumberOfSections;
	}

	/**
	* Returns the file's TimeDateStamp.
	* @return The TimeDateStamp value from the PE header.
	**/
	template<int x>
	dword PeHeaderT<x>::getTimeDateStamp() const
	{
		return m_inthHeader.FileHeader.TimeDateStamp;
	}

	/**
	* Returns the relative virtual address of the file's symbol table.
	* @return The PointerToSymbolTable value from the PE header.
	**/
	template<int x>
	dword PeHeaderT<x>::getPointerToSymbolTable() const
	{
		return m_inthHeader.FileHeader.PointerToSymbolTable;
	}

	/**
	* Returns the number of symbols of the file's symbol table.
	* @return The NumberOfSymbols value from the PE header.
	**/
	template<int x>
	dword PeHeaderT<x>::getNumberOfSymbols() const
	{
		return m_inthHeader.FileHeader.NumberOfSymbols;
	}

	/**
	* Returns the size of optional header of the file.
	* @return The SizeOfOptionalHeader value from the PE header.
	**/
	template<int x>
	word PeHeaderT<x>::getSizeOfOptionalHeader() const
	{
		return m_inthHeader.FileHeader.SizeOfOptionalHeader;
	}

	/**
	* @return The Characteristics value from the PE header.
	**/
	template<int x>
	word PeHeaderT<x>::getCharacteristics() const
	{
		return m_inthHeader.FileHeader.Characteristics;
	}

	/**
	* @return The Magic value from the PE header.
	**/
	template<int x>
	word PeHeaderT<x>::getMagic() const
	{
		return m_inthHeader.OptionalHeader.Magic;
	}

	/**
	* @return The MajorLinkerVersion value from the PE header.
	**/
	template<int x>
	byte PeHeaderT<x>::getMajorLinkerVersion() const
	{
		return m_inthHeader.OptionalHeader.MajorLinkerVersion;
	}

	/**
	* @return The MinorLinkerVersion value from the PE header.
	**/
	template<int x>
	byte PeHeaderT<x>::getMinorLinkerVersion() const
	{
		return m_inthHeader.OptionalHeader.MinorLinkerVersion;
	}

	/**
	* @return The SizeOfCode value from the PE header.
	**/
	template<int x>
	dword PeHeaderT<x>::getSizeOfCode() const
	{
		return m_inthHeader.OptionalHeader.SizeOfCode;
	}

	/**
	* @return The SizeOfInitializedData value from the PE header.
	**/
	template<int x>
	dword PeHeaderT<x>::getSizeOfInitializedData() const
	{
		return m_inthHeader.OptionalHeader.SizeOfInitializedData;
	}

	/**
	* @return The SizeOfUninitializedData value from the PE header.
	**/
	template<int x>
	dword PeHeaderT<x>::getSizeOfUninitializedData() const
	{
		return m_inthHeader.OptionalHeader.SizeOfUninitializedData;
	}

	/**
	* @return The AddressOfEntryPoint value from the PE header.
	**/
	template<int x>
	dword PeHeaderT<x>::getAddressOfEntryPoint() const
	{
		return m_inthHeader.OptionalHeader.AddressOfEntryPoint;
	}

	/**
	* @return The BaseOfCode value from the PE header.
	**/
	template<int x>
	dword PeHeaderT<x>::getBaseOfCode() const
	{
		return m_inthHeader.OptionalHeader.BaseOfCode;
	}

	/**
	* @return The ImageBase value from the PE header.
	**/
	template<int x>
	typename FieldSizes<x>::VAR4_8 PeHeaderT<x>::getImageBase() const
	{
		return m_inthHeader.OptionalHeader.ImageBase;
	}

	/**
	* @return The SectionAlignment value from the PE header.
	**/
	template<int x>
	dword PeHeaderT<x>::getSectionAlignment() const
	{
		return m_inthHeader.OptionalHeader.SectionAlignment;
	}

	/**
	* @return The FileAlignment value from the PE header.
	**/
	template<int x>
	dword PeHeaderT<x>::getFileAlignment() const
	{
		return m_inthHeader.OptionalHeader.FileAlignment;
	}

	/**
	* @return The MajorOperatingSystemVersion value from the PE header.
	**/
	template<int x>
	word PeHeaderT<x>::getMajorOperatingSystemVersion() const
	{
		return m_inthHeader.OptionalHeader.MajorOperatingSystemVersion;
	}

	/**
	* @return The MinorOperatingSystemVersion value from the PE header.
	**/
	template<int x>
	word PeHeaderT<x>::getMinorOperatingSystemVersion() const
	{
		return m_inthHeader.OptionalHeader.MinorOperatingSystemVersion;
	}

	/**
	* @return The MajorImageVersion value from the PE header.
	**/
	template<int x>
	word PeHeaderT<x>::getMajorImageVersion() const
	{
		return m_inthHeader.OptionalHeader.MajorImageVersion;
	}

	/**
	* @return The MinorImageVersion value from the PE header.
	**/
	template<int x>
	word PeHeaderT<x>::getMinorImageVersion() const
	{
		return m_inthHeader.OptionalHeader.MinorImageVersion;
	}

	/**
	* @return The MajorSubsystemVersion value from the PE header.
	**/
	template<int x>
	word PeHeaderT<x>::getMajorSubsystemVersion() const
	{
		return m_inthHeader.OptionalHeader.MajorSubsystemVersion;
	}

	/**
	* @return The MinorSubsystemVersion value from the PE header.
	**/
	template<int x>
	word PeHeaderT<x>::getMinorSubsystemVersion() const
	{
		return m_inthHeader.OptionalHeader.MinorSubsystemVersion;
	}

	/**
	* @return The WinVersionValue value from the PE header.
	**/
	template<int x>
	dword PeHeaderT<x>::getWin32VersionValue() const
	{
		return m_inthHeader.OptionalHeader.Win32VersionValue;
	}

	/**
	* @return The SizeOfImage value from the PE header.
	**/
	template<int x>
	dword PeHeaderT<x>::getSizeOfImage() const
	{
		return m_inthHeader.OptionalHeader.SizeOfImage;
	}

	/**
	* @return The SizeOfHeaders value from the PE header.
	**/
	template<int x>
	dword PeHeaderT<x>::getSizeOfHeaders() const
	{
		return m_inthHeader.OptionalHeader.SizeOfHeaders;
	}

	/**
	* @return The CheckSums value from the PE header.
	**/
	template<int x>
	dword PeHeaderT<x>::getCheckSum() const
	{
		return m_inthHeader.OptionalHeader.CheckSum;
	}

	/**
	* @return The Subsystem value from the PE header.
	**/
	template<int x>
	word PeHeaderT<x>::getSubsystem() const
	{
		return m_inthHeader.OptionalHeader.Subsystem;
	}

	/**
	* @return The DllCharacteristics value from the PE header.
	**/
	template<int x>
	word PeHeaderT<x>::getDllCharacteristics() const
	{
		return m_inthHeader.OptionalHeader.DllCharacteristics;
	}

	/**
	* @return The SizeOfStackReserve value from the PE header.
	**/
	template<int x>
	typename FieldSizes<x>::VAR4_8 PeHeaderT<x>::getSizeOfStackReserve() const
	{
		return m_inthHeader.OptionalHeader.SizeOfStackReserve;
	}

	/**
	* @return The SizeOfStackCommit value from the PE header.
	**/
	template<int x>
	typename FieldSizes<x>::VAR4_8  PeHeaderT<x>::getSizeOfStackCommit() const
	{
		return m_inthHeader.OptionalHeader.SizeOfStackCommit;
	}

	/**
	* @return The SizeOfHeapReserve value from the PE header.
	**/
	template<int x>
	typename FieldSizes<x>::VAR4_8  PeHeaderT<x>::getSizeOfHeapReserve() const
	{
		return m_inthHeader.OptionalHeader.SizeOfHeapReserve;
	}

	/**
	* @return The SizeOfHeapCommit value from the PE header.
	**/
	template<int x>
	typename FieldSizes<x>::VAR4_8  PeHeaderT<x>::getSizeOfHeapCommit() const
	{
		return m_inthHeader.OptionalHeader.SizeOfHeapCommit;
	}

	/**
	* @return The LoaderFlags value from the PE header.
	**/
	template<int x>
	dword PeHeaderT<x>::getLoaderFlags() const
	{
		return m_inthHeader.OptionalHeader.LoaderFlags;
	}

	/**
	* @return The NumberOfRvaAndSizes value from the PE header.
	**/
	template<int x>
	dword PeHeaderT<x>::getNumberOfRvaAndSizes() const
	{
		return m_inthHeader.OptionalHeader.NumberOfRvaAndSizes;
	}

	template<int x>
	dword PeHeaderT<x>::calcNumberOfRvaAndSizes() const
	{
		return static_cast<dword>(m_inthHeader.dataDirectories.size());
	}

	/**
	* Returns the relative virtual address of the current file's export directory.
	* @return The Rva of the Export directory.
	**/
	template<int x>
	dword PeHeaderT<x>::getIddExportRva() const
	{
		return m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	}

	/**
	* Returns the size of the current file's export directory.
	* @return The sizeof the Export directory.
	**/
	template<int x>
	dword PeHeaderT<x>::getIddExportSize() const
	{
		return m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	}

	/**
	* Returns the relative virtual address of the current file's import directory.
	* @return The Rva of the Import directory.
	**/
	template<int x>
	dword PeHeaderT<x>::getIddImportRva() const
	{
		return m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	}

	/**
	* Returns the size of the current file's import directory.
	* @return The size of the Import directory.
	**/
	template<int x>
	dword PeHeaderT<x>::getIddImportSize() const
	{
		return m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_IMPORT].Size;
	}

	/**
	* Returns the relative virtual address of the current file's resource directory.
	* @return The Rva of the Resource directory.
	**/
	template<int x>
	dword PeHeaderT<x>::getIddResourceRva() const
	{
		return m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress;
	}

	/**
	* Returns the size of the current file'resource resource directory.
	* @return The size of the Resource directory.
	**/
	template<int x>
	dword PeHeaderT<x>::getIddResourceSize() const
	{
		return m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_RESOURCE].Size;
	}

	/**
	* Returns the relative virtual address of the current file's exception directory.
	* @return The Rva of the Exception directory.
	**/
	template<int x>
	dword PeHeaderT<x>::getIddExceptionRva() const
	{
		return m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress;
	}

	/**
	* Returns the size of the current file's exception directory.
	* @return The size of the Exception directory.
	**/
	template<int x>
	dword PeHeaderT<x>::getIddExceptionSize() const
	{
		return m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size;
	}

	/**
	* Returns the relative virtual address of the current file's security directory.
	* @return The Rva of the Security directory.
	**/
	template<int x>
	dword PeHeaderT<x>::getIddSecurityRva() const
	{
		return m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress;
	}

	/**
	* Returns the size of the current file's security directory.
	* @return The size of the Security directory.
	**/
	template<int x>
	dword PeHeaderT<x>::getIddSecuritySize() const
	{
		return m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_SECURITY].Size;
	}

	/**
	* Returns the relative virtual address of the current file's base reloc directory.
	* @return The Rva of the Base Reloc directory.
	**/
	template<int x>
	dword PeHeaderT<x>::getIddBaseRelocRva() const
	{
		return m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress;
	}

	/**
	* Returns the size of the current file's base reloc directory.
	* @return The size of the Base Reloc directory.
	**/
	template<int x>
	dword PeHeaderT<x>::getIddBaseRelocSize() const
	{
		return m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;
	}

	/**
	* Returns the relative virtual address of the current file's debug directory.
	* @return The Rva of the Debug directory.
	**/
	template<int x>
	dword PeHeaderT<x>::getIddDebugRva() const
	{
		return m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress;
	}

	/**
	* Returns the size of the current file's debug directory.
	* @return The size of the Debug directory.
	**/
	template<int x>
	dword PeHeaderT<x>::getIddDebugSize() const
	{
		return m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_DEBUG].Size;
	}

	/**
	* Returns the relative virtual address of the current file's Architecture directory.
	* @return The Rva of the Architecture directory.
	**/
	template<int x>
	dword PeHeaderT<x>::getIddArchitectureRva() const
	{
		return m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].VirtualAddress;
	}

	/**
	* Returns the size of the current file's Architecture directory.
	* @return The size of the Architecture directory.
	**/
	template<int x>
	dword PeHeaderT<x>::getIddArchitectureSize() const
	{
		return m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].Size;
	}

	/**
	* Returns the relative virtual address of the current file's global ptr directory.
	* @return The Rva of the GlobalPtr directory.
	**/
	template<int x>
	dword PeHeaderT<x>::getIddGlobalPtrRva() const
	{
		return m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_GLOBALPTR].VirtualAddress;
	}

	/**
	* Returns the size of the current file's global ptr directory.
	* @return The size of the GlobalPtr directory.
	**/
	template<int x>
	dword PeHeaderT<x>::getIddGlobalPtrSize() const
	{
		return m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_GLOBALPTR].Size;
	}

	/**
	* Returns the relative virtual address of the current file's TLS directory.
	* @return The Rva of the Tls directory.
	**/
	template<int x>
	dword PeHeaderT<x>::getIddTlsRva() const
	{
		return m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress;
	}

	/**
	* Returns the size of the current file's TLS directory.
	* @return The size of the Tls directory.
	**/
	template<int x>
	dword PeHeaderT<x>::getIddTlsSize() const
	{
		return m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_TLS].Size;
	}

	/**
	* Returns the relative virtual address of the current file's load config directory.
	* @return The Rva of the LoadConfig directory.
	**/
	template<int x>
	dword PeHeaderT<x>::getIddLoadConfigRva() const
	{
		return m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress;
	}

	/**
	* Returns the size of the current file's load config directory.
	* @return The size of the LoadConfig directory.
	**/
	template<int x>
	dword PeHeaderT<x>::getIddLoadConfigSize() const
	{
		return m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size;
	}

	/**
	* Returns the relative virtual address of the current file's bound import directory.
	* @return The Rva of the BoundImport directory.
	**/
	template<int x>
	dword PeHeaderT<x>::getIddBoundImportRva() const
	{
		return m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].VirtualAddress;
	}

	/**
	* Returns the size of the current file's bound import directory.
	* @return The size of the BoundImport directory.
	**/
	template<int x>
	dword PeHeaderT<x>::getIddBoundImportSize() const
	{
		return m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT].Size;
	}

	/**
	* Returns the relative virtual address of the current file's IAT directory.
	* @return The Rva of the IAT directory.
	**/
	template<int x>
	dword PeHeaderT<x>::getIddIatRva() const
	{
		return m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress;
	}

	/**
	* Returns the size of the current file's IAT directory.
	* @return The size of the IAT directory.
	**/
	template<int x>
	dword PeHeaderT<x>::getIddIatSize() const
	{
		return m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_IAT].Size;
	}

	/**
	* Returns the relative virtual address of the current file's Delay Import directory.
	* @return The Rva of the DelayImport directory.
	**/
	template<int x>
	dword PeHeaderT<x>::getIddDelayImportRva() const
	{
		return m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress;
	}

	/**
	* Returns the size of the current file's Delay Import directory.
	* @return The size of the DelayImport directory.
	**/
	template<int x>
	dword PeHeaderT<x>::getIddDelayImportSize() const
	{
		return m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size;
	}

	/**
	* Returns the relative virtual address of the current file's COM Descriptor directory.
	* @return The Rva of the COM Descriptor directory.
	**/
	template<int x>
	dword PeHeaderT<x>::getIddComHeaderRva() const
	{
		return m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress;
	}

	/**
	* Returns the size of the current file's COM Descriptor directory.
	* @return The Rva of the COM Descriptor directory.
	**/
	template<int x>
	dword PeHeaderT<x>::getIddComHeaderSize() const
	{
		return m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size;
	}

	/**
	* Returns the relative virtual address of an image directory.
	* @param dwDirectory The identifier of an image directory.
	* @return The Rva of the image directory.
	**/
	template<int x>
	dword PeHeaderT<x>::getImageDataDirectoryRva(dword dwDirectory) const
	{
		return m_inthHeader.dataDirectories[dwDirectory].VirtualAddress;
	}

	template<int x>
	void PeHeaderT<x>::setImageDataDirectoryRva(dword dwDirectory, dword value)
	{
		m_inthHeader.dataDirectories[dwDirectory].VirtualAddress = value;
	}

	/**
	* Returns the size of an image directory.
	* @param dwDirectory The identifier of an image directory.
	* @return The size of the image directory.
	**/
	template<int x>
	dword PeHeaderT<x>::getImageDataDirectorySize(dword dwDirectory) const
	{
		return m_inthHeader.dataDirectories[dwDirectory].Size;
	}

	template<int x>
	void PeHeaderT<x>::setImageDataDirectorySize(dword dwDirectory, dword value)
	{
		m_inthHeader.dataDirectories[dwDirectory].Size = value;
	}

	/**
	* Returns the name of the section which is specified by the parameter wSectionnr.
	* @param wSectionnr Index of the section.
	* @return The name of the section.
	**/
	template<int x>
	std::string PeHeaderT<x>::getSectionName(word wSectionnr) const
	{
		std::string sectionName = "";

		for (unsigned int i=0;i<sizeof(m_vIsh[wSectionnr].Name);i++)
		{
			if (m_vIsh[wSectionnr].Name[i]) sectionName += m_vIsh[wSectionnr].Name[i];
		}

		return sectionName;
	}

	template<int x>
	std::string PeHeaderT<x>::getSectionNameFromStringTable(word wSectionnr) const
	{
		return m_vIsh[wSectionnr].StringTableName;
	}

	/**
	* Returns the virtual size of the section which is specified by the parameter wSectionnr.
	* @param wSectionnr Index of the section.
	* @return The virtual size of the section.
	**/
	template<int x>
	dword PeHeaderT<x>::getVirtualSize(word wSectionnr) const
	{
		return m_vIsh[wSectionnr].VirtualSize;
	}

	/**
	* Returns the relative virtual address of the section which is specified by the parameter wSectionnr.
	* @param wSectionnr Index of the section.
	* @return The Rva of the section.
	**/
	template<int x>
	dword PeHeaderT<x>::getVirtualAddress(word wSectionnr) const
	{
		return m_vIsh[wSectionnr].VirtualAddress;
	}

	/**
	* Returns the size of raw data of the section which is specified by the parameter wSectionnr.
	* @param wSectionnr Index of the section.
	* @return The size of raw data of the section.
	**/
	template<int x>
	dword PeHeaderT<x>::getSizeOfRawData(word wSectionnr) const
	{
		return m_vIsh[wSectionnr].SizeOfRawData;
	}

	/**
	* Returns the file offset of the section which is specified by the parameter wSectionnr.
	* @param wSectionnr Index of the section.
	* @return The file offset of the section.
	**/
	template<int x>
	dword PeHeaderT<x>::getPointerToRawData(word wSectionnr) const
	{
		return m_vIsh[wSectionnr].PointerToRawData;
	}

	/**
	* Returns the pointer to relocations of the section which is specified by the parameter wSectionnr.
	* @param wSectionnr Index of the section.
	* @return The pointer to relocations of the section.
	**/
	template<int x>
	dword PeHeaderT<x>::getPointerToRelocations(word wSectionnr) const
	{
		return m_vIsh[wSectionnr].PointerToRelocations;
	}

	/**
	* Returns the poiner to line numbers of the section which is specified by the parameter wSectionnr.
	* @param wSectionnr Index of the section.
	* @return The pointer to line numbers of the section.
	**/
	template<int x>
	dword PeHeaderT<x>::getPointerToLinenumbers(word wSectionnr) const
	{
		return m_vIsh[wSectionnr].PointerToLinenumbers;
	}

	/**
	* Returns the number of relocations of the section which is specified by the parameter wSectionnr.
	* @param wSectionnr Index of the section.
	* @return The number of relocations of the section.
	**/
	template<int x>
	dword PeHeaderT<x>::getNumberOfRelocations(word wSectionnr) const
	{
		return m_vIsh[wSectionnr].NumberOfRelocations;
	}

	/**
	* Returns the number of line numbers of the section which is specified by the parameter wSectionnr.
	* @param wSectionnr Index of the section.
	* @return The number of line numbers of the section.
	**/
	template<int x>
	dword PeHeaderT<x>::getNumberOfLinenumbers(word wSectionnr) const
	{
		return m_vIsh[wSectionnr].NumberOfLinenumbers;
	}

	/**
	* Returns the characteristics of the section which is specified by the parameter wSectionnr.
	* @param wSectionnr Index of the section.
	* @return The characteristics of the section.
	**/
	template<int x>
	dword PeHeaderT<x>::getCharacteristics(word wSectionnr) const
	{
		return m_vIsh[wSectionnr].Characteristics;
	}

	/**
	* Changes the file's Nt signature.
	* @param dwValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setNtSignature(dword dwValue)
	{
		m_inthHeader.Signature = dwValue;
	}

	/**
	* Changes the file's Machine.
	* @param wValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setMachine(word wValue)
	{
		m_inthHeader.FileHeader.Machine = wValue;
	}

	/**
	* Changes the number of sections.
	* @param wValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setNumberOfSections(word wValue)
	{
		m_inthHeader.FileHeader.NumberOfSections = wValue;
	}

	/**
	* Changes the file's TimeDateStamp.
	* @param dwValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setTimeDateStamp(dword dwValue)
	{
		m_inthHeader.FileHeader.TimeDateStamp = dwValue;
	}

	/**
	* Changes the file's PointerToSymbolTable.
	* @param dwValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setPointerToSymbolTable(dword dwValue)
	{
		m_inthHeader.FileHeader.PointerToSymbolTable = dwValue;
	}

	/**
	* Changes the file's NumberOfSymbols.
	* @param dwValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setNumberOfSymbols(dword dwValue)
	{
		m_inthHeader.FileHeader.NumberOfSymbols = dwValue;
	}

	/**
	* Changes the file's SizeOfOptionalHeader.
	* @param wValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setSizeOfOptionalHeader(word wValue)
	{
		m_inthHeader.FileHeader.SizeOfOptionalHeader = wValue;
	}

	/**
	* Changes the file's Characteristics.
	* @param wValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setCharacteristics(word wValue)
	{
		m_inthHeader.FileHeader.Characteristics = wValue;
	}

	/**
	* Changes the file's Magic.
	* @param wValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setMagic(word wValue)
	{
		m_inthHeader.OptionalHeader.Magic = wValue;
	}

	/**
	* Changes the file's MajorLinkerVersion.
	* @param bValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setMajorLinkerVersion(byte bValue)
	{
		m_inthHeader.OptionalHeader.MajorLinkerVersion = bValue;
	}

	/**
	* Changes the file's MinorLinkerVersion.
	* @param bValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setMinorLinkerVersion(byte bValue)
	{
		m_inthHeader.OptionalHeader.MinorLinkerVersion = bValue;
	}

	/**
	* Changes the file's SizeOfCode.
	* @param dwValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setSizeOfCode(dword dwValue)
	{
		m_inthHeader.OptionalHeader.SizeOfCode = dwValue;
	}

	/**
	* Changes the file's SizeOfInitializedData.
	* @param dwValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setSizeOfInitializedData(dword dwValue)
	{
		m_inthHeader.OptionalHeader.SizeOfInitializedData = dwValue;
	}

	/**
	* Changes the file's SizeOfUninitializedData.
	* @param dwValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setSizeOfUninitializedData(dword dwValue)
	{
		m_inthHeader.OptionalHeader.SizeOfUninitializedData = dwValue;
	}

	/**
	* Changes the file's AddressOfEntryPoint.
	* @param dwValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setAddressOfEntryPoint(dword dwValue)
	{
		m_inthHeader.OptionalHeader.AddressOfEntryPoint = dwValue;
	}

	/**
	* Changes the file's BaseOfCode.
	* @param dwValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setBaseOfCode(dword dwValue)
	{
		m_inthHeader.OptionalHeader.BaseOfCode = dwValue;
	}

	/**
	* Changes the file's ImageBase.
	* @param dwValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setImageBase(typename FieldSizes<x>::VAR4_8 dwValue)
	{
		m_inthHeader.OptionalHeader.ImageBase = dwValue;
	}

	/**
	* Changes the file's SectionAlignment.
	* @param dwValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setSectionAlignment(dword dwValue)
	{
		m_inthHeader.OptionalHeader.SectionAlignment = dwValue;
	}

	/**
	* Changes the file's FileAlignment.
	* @param dwValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setFileAlignment(dword dwValue)
	{
		m_inthHeader.OptionalHeader.FileAlignment = dwValue;
	}

	/**
	* Changes the file's MajorOperatingSystemVersion.
	* @param wValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setMajorOperatingSystemVersion(word wValue)
	{
		m_inthHeader.OptionalHeader.MajorOperatingSystemVersion = wValue;
	}

	/**
	* Changes the file's MinorOperatingSystemVersion.
	* @param wValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setMinorOperatingSystemVersion(word wValue)
	{
		m_inthHeader.OptionalHeader.MinorOperatingSystemVersion = wValue;
	}

	/**
	* Changes the file's MajorImageVersion.
	* @param wValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setMajorImageVersion(word wValue)
	{
		m_inthHeader.OptionalHeader.MajorImageVersion = wValue;
	}

	/**
	* Changes the file's MinorImageVersion.
	* @param wValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setMinorImageVersion(word wValue)
	{
		m_inthHeader.OptionalHeader.MinorImageVersion = wValue;
	}

	/**
	* Changes the file's MajorSubsystemVersion.
	* @param wValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setMajorSubsystemVersion(word wValue)
	{
		m_inthHeader.OptionalHeader.MajorSubsystemVersion = wValue;
	}

	/**
	* Changes the file's MinorSubsystemVersion.
	* @param wValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setMinorSubsystemVersion(word wValue)
	{
		m_inthHeader.OptionalHeader.MinorSubsystemVersion = wValue;
	}

	/**
	* Changes the file's Win32VersionValue.
	* @param dwValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setWin32VersionValue(dword dwValue)
	{
		m_inthHeader.OptionalHeader.Win32VersionValue = dwValue;
	}

	/**
	* Changes the file's SizeOfImage.
	* @param dwValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setSizeOfImage(dword dwValue)
	{
		m_inthHeader.OptionalHeader.SizeOfImage = dwValue;
	}

	/**
	* Changes the file's SizeOfHeaders.
	* @param dwValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setSizeOfHeaders(dword dwValue)
	{
		m_inthHeader.OptionalHeader.SizeOfHeaders = dwValue;
	}

	/**
	* Changes the file's CheckSum.
	* @param dwValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setCheckSum(dword dwValue)
	{
		m_inthHeader.OptionalHeader.CheckSum = dwValue;
	}

	/**
	* Changes the file's Subsystem.
	* @param wValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setSubsystem(word wValue)
	{
		m_inthHeader.OptionalHeader.Subsystem = wValue;
	}

	/**
	* Changes the file's DllCharacteristics.
	* @param wValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setDllCharacteristics(word wValue)
	{
		m_inthHeader.OptionalHeader.DllCharacteristics = wValue;
	}

	/**
	* Changes the file's SizeOfStackReserve.
	* @param dwValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setSizeOfStackReserve(typename FieldSizes<x>::VAR4_8 dwValue)
	{
		m_inthHeader.OptionalHeader.SizeOfStackReserve = dwValue;
	}

	/**
	* Changes the file's SizeOfStackCommit.
	* @param dwValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setSizeOfStackCommit(typename FieldSizes<x>::VAR4_8 dwValue)
	{
		m_inthHeader.OptionalHeader.SizeOfStackCommit = dwValue;
	}

	/**
	* Changes the file's SizeOfHeapReserve.
	* @param dwValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setSizeOfHeapReserve(typename FieldSizes<x>::VAR4_8 dwValue)
	{
		m_inthHeader.OptionalHeader.SizeOfHeapReserve = dwValue;
	}

	/**
	* Changes the file's SizeOfHeapCommit.
	* @param dwValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setSizeOfHeapCommit(typename FieldSizes<x>::VAR4_8 dwValue)
	{
		m_inthHeader.OptionalHeader.SizeOfHeapCommit = dwValue;
	}

	/**
	* Changes the file's LoaderFlags.
	* @param dwValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setLoaderFlags(dword dwValue)
	{
		m_inthHeader.OptionalHeader.LoaderFlags = dwValue;
	}

	/**
	* Changes the file's NumberOfRvaAndSizes.
	* @param dwValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setNumberOfRvaAndSizes(dword dwValue)
	{
		m_inthHeader.OptionalHeader.NumberOfRvaAndSizes = dwValue;
	}

	template<int x>
	void PeHeaderT<x>::setIddDebugRva(dword dwValue)
	{
		m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_DEBUG].VirtualAddress = dwValue;
	}

	template<int x>
	void PeHeaderT<x>::setIddDebugSize(dword dwValue)
	{
		m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_DEBUG].Size = dwValue;
	}

	template<int x>
	void PeHeaderT<x>::setIddDelayImportRva(dword dwValue)
	{
		m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].VirtualAddress = dwValue;
	}

	template<int x>
	void PeHeaderT<x>::setIddDelayImportSize(dword dwValue)
	{
		m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT].Size = dwValue;
	}

	template<int x>
	void PeHeaderT<x>::setIddExceptionRva(dword dwValue)
	{
		m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_EXCEPTION].VirtualAddress = dwValue;
	}

	template<int x>
	void PeHeaderT<x>::setIddExceptionSize(dword dwValue)
	{
		m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_EXCEPTION].Size = dwValue;
	}

	template<int x>
	void PeHeaderT<x>::setIddGlobalPtrRva(dword dwValue)
	{
		m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_GLOBALPTR].VirtualAddress = dwValue;
	}

	template<int x>
	void PeHeaderT<x>::setIddGlobalPtrSize(dword dwValue)
	{
		m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_GLOBALPTR].Size = dwValue;
	}

	template<int x>
	void PeHeaderT<x>::setIddIatRva(dword dwValue)
	{
		m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress = dwValue;
	}

	template<int x>
	void PeHeaderT<x>::setIddIatSize(dword dwValue)
	{
		m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_IAT].Size = dwValue;
	}

	template<int x>
	void PeHeaderT<x>::setIddLoadConfigRva(dword dwValue)
	{
		m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].VirtualAddress = dwValue;
	}

	template<int x>
	void PeHeaderT<x>::setIddLoadConfigSize(dword dwValue)
	{
		m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG].Size = dwValue;
	}

	template<int x>
	void PeHeaderT<x>::setIddResourceRva(dword dwValue)
	{
		m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_RESOURCE].VirtualAddress = dwValue;
	}

	template<int x>
	void PeHeaderT<x>::setIddResourceSize(dword dwValue)
	{
		m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_RESOURCE].Size = dwValue;
	}

	template<int x>
	void PeHeaderT<x>::setIddSecurityRva(dword dwValue)
	{
		m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_SECURITY].VirtualAddress = dwValue;
	}

	template<int x>
	void PeHeaderT<x>::setIddSecuritySize(dword dwValue)
	{
		m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_SECURITY].Size = dwValue;
	}

	template<int x>
	void PeHeaderT<x>::setIddTlsRva(dword dwValue)
	{
		m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress = dwValue;
	}

	template<int x>
	void PeHeaderT<x>::setIddTlsSize(dword dwValue)
	{
		m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_TLS].Size = dwValue;
	}

	/**
	* Changes the rva of the file's export directory.
	* @param dwValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setIddExportRva(dword dwValue)
	{
		m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress = dwValue;
	}

	/**
	* Changes the size of the file's export directory.
	* @param dwValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setIddExportSize(dword dwValue)
	{
		m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_EXPORT].Size = dwValue;
	}

	template<int x>
	void PeHeaderT<x>::setIddBaseRelocRva(dword value)
	{
		m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = value;
	}

	template<int x>
	void PeHeaderT<x>::setIddBaseRelocSize(dword value)
	{
		m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = value;
	}

	template<int x>
	void PeHeaderT<x>::setIddArchitectureRva(dword value)
	{
		m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].VirtualAddress = value;
	}

	template<int x>
	void PeHeaderT<x>::setIddArchitectureSize(dword value)
	{
		m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_ARCHITECTURE].Size = value;
	}

	template<int x>
	void PeHeaderT<x>::setIddComHeaderRva(dword value)
	{
		m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].VirtualAddress = value;
	}

	template<int x>
	void PeHeaderT<x>::setIddComHeaderSize(dword value)
	{
		m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR].Size = value;
	}

	/**
	* Changes the rva of the file's import directory.
	* @param dwValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setIddImportRva(dword dwValue)
	{
		m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress = dwValue;
	}

	/**
	* Changes the size of the file's import directory.
	* @param dwValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setIddImportSize(dword dwValue)
	{
		m_inthHeader.dataDirectories[PELIB_IMAGE_DIRECTORY_ENTRY_IMPORT].Size = dwValue;
	}

	/**
	* Changes the name of a section.
	* @param wSectionnr Identifier of the section
	* @param strName New name.
	**/
	template<int x>
	void PeHeaderT<x>::setSectionName(word wSectionnr, std::string strName)
	{
		strncpy(reinterpret_cast<char*>(m_vIsh[wSectionnr].Name), strName.c_str(), sizeof(m_vIsh[wSectionnr].Name));
	}

	/**
	* Changes the virtual size of a section.
	* @param wSectionnr Identifier of the section
	* @param dwValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setVirtualSize(word wSectionnr, dword dwValue)
	{
		m_vIsh[wSectionnr].VirtualSize = dwValue;
	}

	/**
	* Changes the virtual address of a section.
	* @param wSectionnr Identifier of the section
	* @param dwValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setVirtualAddress(word wSectionnr, dword dwValue)
	{
		m_vIsh[wSectionnr].VirtualAddress = dwValue;
	}

	/**
	* Changes the size of raw data of a section.
	* @param wSectionnr Identifier of the section
	* @param dwValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setSizeOfRawData(word wSectionnr, dword dwValue)
	{
		m_vIsh[wSectionnr].SizeOfRawData = dwValue;
	}

	/**
	* Changes the size of raw data of a section.
	* @param wSectionnr Identifier of the section
	* @param dwValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setPointerToRawData(word wSectionnr, dword dwValue)
	{
		m_vIsh[wSectionnr].PointerToRawData = dwValue;
	}

	/**
	* Changes the pointer to relocations of a section.
	* @param wSectionnr Identifier of the section
	* @param dwValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setPointerToRelocations(word wSectionnr, dword dwValue)
	{
		m_vIsh[wSectionnr].PointerToRelocations = dwValue;
	}

	/**
	* Changes the pointer to line numbers of a section.
	* @param wSectionnr Identifier of the section
	* @param dwValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setPointerToLinenumbers(word wSectionnr, dword dwValue)
	{
		m_vIsh[wSectionnr].PointerToLinenumbers = dwValue;
	}

	/**
	* Changes the number of relocations of a section.
	* @param wSectionnr Identifier of the section
	* @param dwValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setNumberOfRelocations(word wSectionnr, dword dwValue)
	{
		m_vIsh[wSectionnr].NumberOfRelocations = dwValue;
	}

	/**
	* Changes the number of line numbers of a section.
	* @param wSectionnr Identifier of the section
	* @param dwValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setNumberOfLinenumbers(word wSectionnr, dword dwValue)
	{
		m_vIsh[wSectionnr].NumberOfLinenumbers = dwValue;
	}

	/**
	* Changes the characteristics of a section.
	* @param wSectionnr Identifier of the section
	* @param dwValue New value.
	**/
	template<int x>
	void PeHeaderT<x>::setCharacteristics(word wSectionnr, dword dwValue)
	{
		m_vIsh[wSectionnr].Characteristics = dwValue;
	}

}

#endif
