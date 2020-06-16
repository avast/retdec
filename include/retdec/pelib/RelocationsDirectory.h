/*
* Relocations.h - Part of the PeLib library.
*
* Copyright (c) 2004 - 2005 Sebastian Porst (webmaster@the-interweb.com)
* All rights reserved.
*
* This software is licensed under the zlib/libpng License.
* For more details see http://www.opensource.org/licenses/zlib-license.php
* or the license information file (license.htm) in the root directory
* of PeLib.
*/

#ifndef RELOCATIONSDIRECTORY_H
#define RELOCATIONSDIRECTORY_H

#include "retdec/pelib/PeHeader.h"

namespace PeLib
{
	/// Class that handles the relocations directory.
	/**
	* This class handles the relocations directory.
	**/
	class RelocationsDirectory
	{
		protected:
		  std::vector<IMG_BASE_RELOC> m_vRelocations; ///< Used to store the relocation data.
		  LoaderError m_ldrError;                     /// Error detected by the import table parser

		  void read(InputBuffer& inputbuffer, unsigned int uiSize, unsigned int sizeOfImage);

		public:
		  /// Constructor and destructor
		  RelocationsDirectory();
		  virtual ~RelocationsDirectory() = default;

		  /// Retrieve the loader error
		  LoaderError loaderError() const;
		  void setLoaderError(LoaderError ldrError);

		  /// Returns the number of relocations in the relocations directory.
		  unsigned int calcNumberOfRelocations() const; // EXPORT
		  /// Returns the number of relocation data entries of a specific relocation.
		  unsigned int calcNumberOfRelocationData(unsigned int ulRelocation) const; // EXPORT

		  /// Read a file's relocations directory.
		  int read(const unsigned char* buffer, unsigned int buffersize, unsigned int sizeOfImage); // EXPORT
		  /// Returns the size of the relocations directory.
		  unsigned int size() const; // EXPORT

		  /// Returns the VA of a relocation.
		  std::uint32_t getVirtualAddress(unsigned int ulRelocation) const; // EXPORT
		  /// Returns the SizeOfBlock value of a relocation.
		  std::uint32_t getSizeOfBlock(unsigned int ulRelocation) const; // EXPORT
		  /// Returns the RelocationData of a relocation.
		  std::uint16_t getRelocationData(unsigned int ulRelocation, unsigned int ulDataNumber) const; // EXPORT

		  /// Changes the relocation data of a relocation.
		  void setRelocationData(unsigned int ulRelocation, unsigned int ulDataNumber, std::uint16_t wData); // EXPORT

		  /// Changes the VirtualAddress of a relocation.
		  void setVirtualAddress(unsigned int ulRelocation, std::uint32_t dwValue); // EXPORT
		  /// Changes the SizeOfBlock of a relocation.
		  void setSizeOfBlock(unsigned int ulRelocation, std::uint32_t dwValue); // EXPORT

		  void addRelocation(); // EXPORT
		  /// Adds new data to a relocation.
		  void addRelocationData(unsigned int ulRelocation, std::uint16_t wValue); // EXPORT
		  /// Removes data from a relocation.
		  void removeRelocationData(unsigned int ulRelocation, std::uint16_t wValue); // EXPORT
		  void removeRelocation(unsigned int index); // EXPORT
		  void removeRelocationData(unsigned int relocindex, unsigned int dataindex); // EXPORT
	};

	template <int bits>
	class RelocationsDirectoryT : public RelocationsDirectory
	{
		public:
		  /// Read a file's relocations directory.
		  int read(std::istream& inStream, const PeHeaderT<bits>& peHeader); // EXPORT
	};

	template <int bits>
	int RelocationsDirectoryT<bits>::read(
			std::istream& inStream,
			const PeHeaderT<bits>& peHeader)
	{
		IStreamWrapper inStream_w(inStream);
		std::uint64_t ulFileSize = fileSize(inStream_w);

		if (!inStream_w)
		{
			return ERROR_OPENING_FILE;
		}

		unsigned int uiOffset = peHeader.rvaToOffset(peHeader.getIddBaseRelocRva());
		unsigned int uiSize = peHeader.getIddBaseRelocSize();

		// Check whether the relocations are out of the image
		if(uiOffset == std::numeric_limits<unsigned int>::max())
		{
			RelocationsDirectory::setLoaderError(LDR_ERROR_RELOCATIONS_OUT_OF_IMAGE);
			return ERROR_INVALID_FILE;
		}

		// If uiSize is big enough it can overflow after addition with uiOffset, ulFileSize < uiOffset + uiSize can be true,
		//   even though it should be false.
		if (uiSize > ulFileSize || (uiOffset + uiSize) > ulFileSize)
		{
			RelocationsDirectory::setLoaderError(LDR_ERROR_RELOCATIONS_OUT_OF_IMAGE);
			return ERROR_INVALID_FILE;
		}

		inStream_w.seekg(uiOffset, std::ios::beg);

		std::vector<unsigned char> vRelocDirectory(uiSize);
		inStream_w.read(reinterpret_cast<char*>(vRelocDirectory.data()), uiSize);

		InputBuffer ibBuffer{vRelocDirectory};
		RelocationsDirectory::read(ibBuffer, uiSize, (unsigned int)peHeader.getSizeOfImage());

		return ERROR_NONE;
	}
}

#endif
