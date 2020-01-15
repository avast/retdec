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

#ifndef DEBUGDIRECTORY_H
#define DEBUGDIRECTORY_H

#include "pelib/PeHeader.h"

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

		  std::vector<PELIB_IMG_DEBUG_DIRECTORY> read(InputBuffer& ibBuffer, unsigned int uiRva, unsigned int uiSize);

		public:
		  virtual ~DebugDirectory() = default;

		  void clear(); // EXPORT
		  /// Reads the Debug directory from a file.
		  int read(unsigned char* buffer, unsigned int buffersize);
		  /// Rebuilds the current Debug directory.
		  void rebuild(std::vector<byte>& obBuffer) const; // EXPORT
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
		  dword getCharacteristics(std::size_t uiIndex) const; // EXPORT
		  /// Returns the TimeDateStamp value of a debug structure.
		  dword getTimeDateStamp(std::size_t uiIndex) const; // EXPORT
		  /// Returns the MajorVersion value of a debug structure.
		  word getMajorVersion(std::size_t uiIndex) const; // EXPORT
		  /// Returns the MinorVersion value of a debug structure.
		  word getMinorVersion(std::size_t uiIndex) const; // EXPORT
		  /// Returns the Type value of a debug structure.
		  dword getType(std::size_t uiIndex) const; // EXPORT
		  /// Returns the SizeOfData value of a debug structure.
		  dword getSizeOfData(std::size_t uiIndex) const; // EXPORT
		  /// Returns the AddressOfRawData value of a debug structure.
		  dword getAddressOfRawData(std::size_t uiIndex) const; // EXPORT
		  /// Returns the PointerToRawData value of a debug structure.
		  dword getPointerToRawData(std::size_t uiIndex) const; // EXPORT
		  std::vector<byte> getData(std::size_t index) const; // EXPORT

		  /// Sets the Characteristics value of a debug structure.
		  void setCharacteristics(std::size_t uiIndex, dword dwValue); // EXPORT
		  /// Sets the TimeDateStamp value of a debug structure.
		  void setTimeDateStamp(std::size_t uiIndex, dword dwValue); // EXPORT
		  /// Sets the MajorVersion value of a debug structure.
		  void setMajorVersion(std::size_t uiIndex, word wValue); // EXPORT
		  /// Sets the MinorVersion value of a debug structure.
		  void setMinorVersion(std::size_t uiIndex, word wValue); // EXPORT
		  /// Sets the Type value of a debug structure.
		  void setType(std::size_t uiIndex, dword dwValue); // EXPORT
		  /// Sets the SizeOfData value of a debug structure.
		  void setSizeOfData(std::size_t uiIndex, dword dwValue); // EXPORT
		  /// Sets the AddressOfRawData value of a debug structure.
		  void setAddressOfRawData(std::size_t uiIndex, dword dwValue); // EXPORT
		  /// Sets the PointerToRawData value of a debug structure.
		  void setPointerToRawData(std::size_t uiIndex, dword dwValue); // EXPORT
		  void setData(std::size_t index, const std::vector<byte>& data); // EXPORT

		  const std::vector<std::pair<unsigned int, unsigned int>>& getOccupiedAddresses() const;
	};

	template <int bits>
	class DebugDirectoryT : public DebugDirectory
	{
		public:
		  /// Reads the Debug directory from a file.
		  int read(std::istream& inStream, const PeHeaderT<bits>& peHeader);
	};

	/**
	* @param inStream Input stream.
	* @param peHeader A valid PE header which is necessary because some RVA calculations need to be done.
	**/
	template <int bits>
	int DebugDirectoryT<bits>::read(std::istream& inStream, const PeHeaderT<bits>& peHeader)
	{
		IStreamWrapper inStream_w(inStream);

		if (!inStream_w)
		{
			return ERROR_OPENING_FILE;
		}

		std::uint64_t ulFileSize = fileSize(inStream_w);

		unsigned int uiRva = peHeader.getIddDebugRva();
		unsigned int uiOffset = peHeader.rvaToOffset(uiRva);
		unsigned int uiSize = peHeader.getIddDebugSize();

		if (ulFileSize < uiOffset + uiSize)
		{
			return ERROR_INVALID_FILE;
		}

		inStream_w.seekg(uiOffset, std::ios::beg);

		std::vector<byte> vDebugDirectory(uiSize);
		inStream_w.read(reinterpret_cast<char*>(vDebugDirectory.data()), uiSize);

		InputBuffer ibBuffer{vDebugDirectory};

		std::vector<PELIB_IMG_DEBUG_DIRECTORY> currDebugInfo = DebugDirectory::read(ibBuffer, uiRva, uiSize);

		for (unsigned int i=0;i<currDebugInfo.size();i++)
		{
			if ((currDebugInfo[i].idd.PointerToRawData >= ulFileSize) ||
				(currDebugInfo[i].idd.PointerToRawData + currDebugInfo[i].idd.SizeOfData >= ulFileSize))
			{
				return ERROR_INVALID_FILE;
			}

			inStream_w.seekg(currDebugInfo[i].idd.PointerToRawData, std::ios::beg);
			currDebugInfo[i].data.resize(currDebugInfo[i].idd.SizeOfData);
			inStream_w.read(reinterpret_cast<char*>(currDebugInfo[i].data.data()), currDebugInfo[i].idd.SizeOfData);
			if (!inStream_w) return ERROR_INVALID_FILE;

			if (currDebugInfo[i].idd.SizeOfData > 0)
			{
				m_occupiedAddresses.push_back(
						std::make_pair(
							currDebugInfo[i].idd.AddressOfRawData,
							currDebugInfo[i].idd.AddressOfRawData + currDebugInfo[i].idd.SizeOfData - 1
						));
			}
		}

		std::swap(currDebugInfo, m_vDebugInfo);

		return ERROR_NONE;
	}
}
#endif
