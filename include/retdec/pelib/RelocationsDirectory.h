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

#ifndef RETDEC_PELIB_RELOCATIONSDIRECTORY_H
#define RETDEC_PELIB_RELOCATIONSDIRECTORY_H

#include "retdec/pelib/ImageLoader.h"

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

		public:
		  /// Constructor and destructor
		  RelocationsDirectory();
		  virtual ~RelocationsDirectory() = default;

		  /// Read a file's relocations directory.
		  int read(ImageLoader & imageLoader); // EXPORT

		  /// Retrieve the loader error
		  LoaderError loaderError() const;
		  void setLoaderError(LoaderError ldrError);

		  /// Returns the number of relocations in the relocations directory.
		  unsigned int calcNumberOfRelocations() const; // EXPORT
		  /// Returns the number of relocation data entries of a specific relocation.
		  unsigned int calcNumberOfRelocationData(unsigned int ulRelocation) const; // EXPORT

		  /// Read a file's relocations directory.
		  void read(const std::uint8_t * data, std::uint32_t uiSize, std::uint32_t sizeOfImage);
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
}

#endif
