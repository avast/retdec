/*
* IatDirectory.h - Part of the PeLib library.
*
* Copyright (c) 2004 - 2005 Sebastian Porst (webmaster@the-interweb.com)
* All rights reserved.
*
* This software is licensed under the zlib/libpng License.
* For more details see http://www.opensource.org/licenses/zlib-license.php
* or the license information file (license.htm) in the root directory
* of PeLib.
*/

#ifndef RETDEC_PELIB_IATDIRECTORY_H
#define RETDEC_PELIB_IATDIRECTORY_H

#include "retdec/pelib/PeLibInc.h"
#include "retdec/pelib/ImageLoader.h"

namespace PeLib
{
	/// Class that handles the Import Address Table (IAT)
	/**
	* This class can read and modify the Import Address Table of a PE file.
	**/
	class IatDirectory
	{
		protected:
		  std::vector<std::uint32_t> m_vIat; ///< Stores the individual IAT fields.

		public:
		  virtual ~IatDirectory() = default;

		  /// Reads the Import Address Table from a PE file.
		  int read(const void * buffer, std::size_t buffersize); // EXPORT
		  /// Reads the Import Address Table from an image loader
		  int read(PeLib::ImageLoader & imageLoader); // EXPORT
		  /// Returns the number of fields in the IAT.
		  unsigned int calcNumberOfAddresses() const; // EXPORT
		  /// Adds another address to the IAT.
		  void addAddress(std::uint32_t dwValue); // EXPORT
		  /// Removes an address from the IAT.
		  void removeAddress(unsigned int index); // EXPORT
		  /// Empties the IAT.
		  void clear(); // EXPORT
		  // Rebuilds the IAT.
		  void rebuild(std::vector<std::uint8_t>& vBuffer) const; // EXPORT
		  /// Returns the size of the current IAT.
		  unsigned int size() const; // EXPORT
		  /// Writes the current IAT to a file.
		  int write(const std::string& strFilename, unsigned int uiOffset) const; // EXPORT

		  /// Retrieve the value of a field in the IAT.
		  std::uint32_t getAddress(unsigned int index) const; // EXPORT
		  /// Change the value of a field in the IAT.
		  void setAddress(std::uint32_t dwAddrnr, std::uint32_t dwValue); // EXPORT
	};
}

#endif

