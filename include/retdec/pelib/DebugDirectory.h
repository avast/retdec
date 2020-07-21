/*
* DebugDirectory.h - Part of the PeLib library.
*
* Copyright (c) 2004 - 2005 Sebastian Porst (webmaster@the-interweb.com)
* All rights reserved.
*
* This software is licensed under the zlib/libpng License.
* For more details see http://www.opensource.org/licenses/zlib-license.php
* or the license information file (license.htm) in the root directory
* of PeLib.
*/

#ifndef RETDEC_PELIB_DEBUGDIRECTORY_H
#define RETDEC_PELIB_DEBUGDIRECTORY_H

#include "retdec/pelib/ImageLoader.h"

namespace PeLib
{
	/// Class that handles the Debug directory.
	class DebugDirectory
	{
		protected:
		  /// Stores the various DebugDirectory structures.
		  std::vector<PELIB_IMG_DEBUG_DIRECTORY> m_vDebugInfo;
		  /// Stores RVAs which are occupied by this debug directory.
		  std::vector<std::pair<unsigned int, unsigned int>> m_occupiedAddresses;

		  void read(ImageLoader & imageLoader, std::vector<PELIB_IMG_DEBUG_DIRECTORY> & debugInfo, std::uint32_t rva, std::uint32_t size);

		public:
		  virtual ~DebugDirectory() = default;

		  /// Reads the Debug directory from a file.
		  int read(std::istream& inStream, ImageLoader & imageLoader);
		  ///
		  void clear(); // EXPORT
		  /// Rebuilds the current Debug directory.
		  void rebuild(std::vector<std::uint8_t>& obBuffer) const; // EXPORT
		  /// Returns the size the current Debug directory needs after rebuilding.
		  unsigned int size() const;
		  /// Writes the current Debug directory back to a file.
		  int write(const std::string& strFilename, unsigned int uiOffset) const; // EXPORT

		  /// Returns the number of DebugDirectory image structures in the current DebugDirectory.
		  unsigned int calcNumberOfEntries() const; // EXPORT

		  /// Adds a new debug structure.
		  void addEntry(); // EXPORT
		  /// Removes a debug structure.
		  void removeEntry(std::size_t uiIndex); // EXPORT

		  /// Returns the Characteristics value of a debug structure.
		  std::uint32_t getCharacteristics(std::size_t uiIndex) const; // EXPORT
		  /// Returns the TimeDateStamp value of a debug structure.
		  std::uint32_t getTimeDateStamp(std::size_t uiIndex) const; // EXPORT
		  /// Returns the MajorVersion value of a debug structure.
		  std::uint16_t getMajorVersion(std::size_t uiIndex) const; // EXPORT
		  /// Returns the MinorVersion value of a debug structure.
		  std::uint16_t getMinorVersion(std::size_t uiIndex) const; // EXPORT
		  /// Returns the Type value of a debug structure.
		  std::uint32_t getType(std::size_t uiIndex) const; // EXPORT
		  /// Returns the SizeOfData value of a debug structure.
		  std::uint32_t getSizeOfData(std::size_t uiIndex) const; // EXPORT
		  /// Returns the AddressOfRawData value of a debug structure.
		  std::uint32_t getAddressOfRawData(std::size_t uiIndex) const; // EXPORT
		  /// Returns the PointerToRawData value of a debug structure.
		  std::uint32_t getPointerToRawData(std::size_t uiIndex) const; // EXPORT
		  std::vector<std::uint8_t> getData(std::size_t index) const; // EXPORT

		  /// Sets the Characteristics value of a debug structure.
		  void setCharacteristics(std::size_t uiIndex, std::uint32_t dwValue); // EXPORT
		  /// Sets the TimeDateStamp value of a debug structure.
		  void setTimeDateStamp(std::size_t uiIndex, std::uint32_t dwValue); // EXPORT
		  /// Sets the MajorVersion value of a debug structure.
		  void setMajorVersion(std::size_t uiIndex, std::uint16_t wValue); // EXPORT
		  /// Sets the MinorVersion value of a debug structure.
		  void setMinorVersion(std::size_t uiIndex, std::uint16_t wValue); // EXPORT
		  /// Sets the Type value of a debug structure.
		  void setType(std::size_t uiIndex, std::uint32_t dwValue); // EXPORT
		  /// Sets the SizeOfData value of a debug structure.
		  void setSizeOfData(std::size_t uiIndex, std::uint32_t dwValue); // EXPORT
		  /// Sets the AddressOfRawData value of a debug structure.
		  void setAddressOfRawData(std::size_t uiIndex, std::uint32_t dwValue); // EXPORT
		  /// Sets the PointerToRawData value of a debug structure.
		  void setPointerToRawData(std::size_t uiIndex, std::uint32_t dwValue); // EXPORT
		  void setData(std::size_t index, const std::vector<std::uint8_t>& data); // EXPORT

		  const std::vector<std::pair<unsigned int, unsigned int>>& getOccupiedAddresses() const;
	};
}
#endif
