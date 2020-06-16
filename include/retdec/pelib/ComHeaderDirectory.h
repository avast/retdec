/*
* ComHeaderDirectory.h - Part of the PeLib library.
*
* Copyright (c) 2004 - 2005 Sebastian Porst (webmaster@the-interweb.com)
* All rights reserved.
*
* This software is licensed under the zlib/libpng License.
* For more details see http://www.opensource.org/licenses/zlib-license.php
* or the license information file (license.htm) in the root directory
* of PeLib.
*/

#ifndef COMHEADERDIRECTORY_H
#define COMHEADERDIRECTORY_H

#include "retdec/pelib/PeHeader.h"

namespace PeLib
{
	/// Class that handles the COM+ descriptor directory.
	/**
	* This class handles the COM+ Descriptor directory which was added to PE files
	* which work with the .NET runtime modules.
	**/
	class ComHeaderDirectory
	{
		protected:
		  PELIB_IMAGE_COR20_HEADER m_ichComHeader; ///< The COM+ descriptor.

		  void read(InputBuffer& inputbuffer);

		public:
		  virtual ~ComHeaderDirectory() = default;

		  /// Read a file's COM+ runtime descriptor directory.
		  int read(unsigned char* buffer, unsigned int buffersize); // EXPORT
		  /// Rebuild the COM+ descriptor.
		  void rebuild(std::vector<std::uint8_t>& vBuffer) const; // EXPORT
		  /// Returns the size of the current COM+ descriptor.
		  unsigned int size() const; // EXPORT
		  /// Writes the current COM+ descriptor directory to a file.
		  int write(const std::string& strFilename, unsigned int dwOffset) const; // EXPORT

		  /// Get the COM+ descriptor's SizeOfHeader (cb) value.
		  std::uint32_t getSizeOfHeader() const; // EXPORT
		  /// Get the COM+ descriptor's MajorRuntimeVersion value.
		  std::uint16_t getMajorRuntimeVersion() const; // EXPORT
		  /// Get the COM+ descriptor's MinorRuntimeVersion value.
		  std::uint16_t getMinorRuntimeVersion() const; // EXPORT
		  /// Get the COM+ descriptor's MetaData (Virtual Address) value.
		  std::uint32_t getMetaDataVa() const; // EXPORT
		  /// Get the COM+ descriptor's MetaData (Size) value.
		  std::uint32_t getMetaDataSize() const; // EXPORT
		  /// Get the COM+ descriptor's Flags value.
		  std::uint32_t getFlags() const; // EXPORT
		  /// Get the COM+ descriptor's EntryPointToken value.
		  std::uint32_t getEntryPointToken() const; // EXPORT
		  /// Get the COM+ descriptor's Resources (Virtual Address) value.
		  std::uint32_t getResourcesVa() const; // EXPORT
		  /// Get the COM+ descriptor's Resources (Size) value.
		  std::uint32_t getResourcesSize() const; // EXPORT
		  /// Get the COM+ descriptor's StrongNameSignature (Virtual Address) value.
		  std::uint32_t getStrongNameSignatureVa() const; // EXPORT
		  /// Get the COM+ descriptor's StrongNameSignature (Size) value.
		  std::uint32_t getStrongNameSignatureSize() const; // EXPORT
		  /// Get the COM+ descriptor's CodeManagerTable (Virtual Address) value.
		  std::uint32_t getCodeManagerTableVa() const; // EXPORT
		  /// Get the COM+ descriptor's CodeManagerTable (Size) value.
		  std::uint32_t getCodeManagerTableSize() const; // EXPORT
		  /// Get the COM+ descriptor's VTableFixup (Virtual Address) value.
		  std::uint32_t getVTableFixupsVa() const; // EXPORT
		  /// Get the COM+ descriptor's VTableFixup (Size) value.
		  std::uint32_t getVTableFixupsSize() const; // EXPORT
		  /// Get the COM+ descriptor's ExportAddressTable (Virtual Address) value.
		  std::uint32_t getExportAddressTableJumpsVa() const; // EXPORT
		  /// Get the COM+ descriptor's ExportAddressTable (Size) value.
		  std::uint32_t getExportAddressTableJumpsSize() const; // EXPORT
		  /// Get the COM+ descriptor's ManagedNativeHeader (Virtual Address) value.
		  std::uint32_t getManagedNativeHeaderVa() const; // EXPORT
		  /// Get the COM+ descriptor's ManagedNativeHeader (Size) value.
		  std::uint32_t getManagedNativeHeaderSize() const; // EXPORT

		  /// Change the COM+ descriptor's SizeOfHeader (cb) value.
		  void setSizeOfHeader(std::uint32_t dwValue); // EXPORT
		  /// Change the COM+ descriptor's MajorRuntimeVersion value.
		  void setMajorRuntimeVersion(std::uint16_t wValue); // EXPORT
		  /// Change the COM+ descriptor's MinorRuntimeVersion value.
		  void setMinorRuntimeVersion(std::uint16_t wValue); // EXPORT
		  /// Change the COM+ descriptor's MetaData (VirtualAddress) value.
		  void setMetaDataVa(std::uint32_t dwValue); // EXPORT
		  /// Change the COM+ descriptor's MetaData (Size) value.
		  void setMetaDataSize(std::uint32_t dwValue); // EXPORT
		  /// Change the COM+ descriptor's Flags value.
		  void setFlags(std::uint32_t dwValue); // EXPORT
		  /// Change the COM+ descriptor's EntryPointToken value.
		  void setEntryPointToken(std::uint32_t dwValue); // EXPORT
		  /// Change the COM+ descriptor's Resources (VirtualAddress) value.
		  void setResourcesVa(std::uint32_t dwValue); // EXPORT
		  /// Change the COM+ descriptor's Resources (Size) value.
		  void setResourcesSize(std::uint32_t dwValue); // EXPORT
		  /// Change the COM+ descriptor's StrongNameSignatureVa (VirtualAddress) value.
		  void setStrongNameSignatureVa(std::uint32_t dwValue); // EXPORT
		  /// Change the COM+ descriptor's StrongNameSignatureVa (Size) value.
		  void setStrongNameSignagureSize(std::uint32_t dwValue); // EXPORT
		  /// Change the COM+ descriptor's CodeManagerTable (VirtualAddress) value.
		  void setCodeManagerTableVa(std::uint32_t dwValue); // EXPORT
		  /// Change the COM+ descriptor's CodeManagerTable (Size) value.
		  void setCodeManagerTableSize(std::uint32_t dwValue); // EXPORT
		  /// Change the COM+ descriptor's VTableFixups (VirtualAddress) value.
		  void setVTableFixupsVa(std::uint32_t dwValue); // EXPORT
		  /// Change the COM+ descriptor's VTableFixups (Size) value.
		  void setVTableFixupsSize(std::uint32_t dwValue); // EXPORT
		  /// Change the COM+ descriptor's ExportAddressTableJumps (VirtualAddress) value.
		  void setExportAddressTableJumpsVa(std::uint32_t dwValue); // EXPORT
		  /// Change the COM+ descriptor's ExportAddressTableJumps (Size) value.
		  void setExportAddressTableJumpsSize(std::uint32_t dwValue); // EXPORT
		  /// Change the COM+ descriptor's ManagedNativeHeader (VirtualAddress) value.
		  void setManagedNativeHeaderVa(std::uint32_t dwValue); // EXPORT
		  /// Change the COM+ descriptor's ManagedNativeHeader (Size) value.
		  void setManagedNativeHeaderSize(std::uint32_t dwValue); // EXPORT
	};

	template <int bits>
	class ComHeaderDirectoryT : public ComHeaderDirectory
	{
		public:
		  /// Read a file's COM+ runtime descriptor directory.
		  int read(std::istream& inStream, const PeHeaderT<bits>& peHeader); // EXPORT
	};

	/**
	* Reads a file's COM+ descriptor.
	* @param inStream Input stream.
	* @param peHeader A valid PE header which is necessary because some RVA calculations need to be done.
	**/
	template <int bits>
	int ComHeaderDirectoryT<bits>::read(std::istream& inStream, const PeHeaderT<bits>& peHeader)
	{
		IStreamWrapper inStream_w(inStream);

		if (!inStream_w)
		{
			return ERROR_OPENING_FILE;
		}

		std::uint64_t ulFileSize = fileSize(inStream_w);

		unsigned int uiOffset = peHeader.rvaToOffset(peHeader.getIddComHeaderRva());
		unsigned int uiSize = peHeader.getIddComHeaderSize();

		if (ulFileSize < uiOffset + uiSize)
		{
			return ERROR_INVALID_FILE;
		}

		inStream_w.seekg(uiOffset, std::ios::beg);

		std::vector<std::uint8_t> vComDescDirectory(uiSize);
		inStream_w.read(reinterpret_cast<char*>(vComDescDirectory.data()), uiSize);

		InputBuffer ibBuffer{vComDescDirectory};
		ComHeaderDirectory::read(ibBuffer);
		return ERROR_NONE;
	}
}
#endif
