/*
* DebugDirectory.cpp - Part of the PeLib library.
*
* Copyright (c) 2004 - 2005 Sebastian Porst (webmaster@the-interweb.com)
* All rights reserved.
*
* This software is licensed under the zlib/libpng License.
* For more details see http://www.opensource.org/licenses/zlib-license.php
* or the license information file (license.htm) in the root directory
* of PeLib.
*/

#include "retdec/pelib/PeLibInc.h"
#include "retdec/pelib/DebugDirectory.h"

namespace PeLib
{
	/**
	* @param inStream Input stream.
	* @param imageLoader A valid image loader reference which is necessary because some RVA calculations need to be done.
	**/

	int DebugDirectory::read(std::istream& inStream, ImageLoader & imageLoader)
	{
		std::vector<PELIB_IMG_DEBUG_DIRECTORY> debugInfo;
		std::uint64_t ulFileSize = fileSize(inStream);
		std::size_t rva = imageLoader.getDataDirRva(PELIB_IMAGE_DIRECTORY_ENTRY_DEBUG);
		std::size_t size = imageLoader.getDataDirSize(PELIB_IMAGE_DIRECTORY_ENTRY_DEBUG);
		std::size_t sizeOfImage = imageLoader.getSizeOfImage();
		if ((rva + size) < rva || (rva + size) > sizeOfImage)
		{
			return ERROR_INVALID_FILE;
		}

		// Read the array of debug directories
		read(imageLoader, debugInfo, rva, size);

		// For each debug directory, also read its data
		for(auto & debugEntry : debugInfo)
		{
			if ((debugEntry.idd.PointerToRawData + debugEntry.idd.SizeOfData) < debugEntry.idd.PointerToRawData ||
				(debugEntry.idd.PointerToRawData >= ulFileSize) ||
				(debugEntry.idd.PointerToRawData + debugEntry.idd.SizeOfData >= ulFileSize))
			{
				return ERROR_INVALID_FILE;
			}

			// Load the debug info data from the file, not from the image.
			// Some samples may have debug info part of the overlay
			debugEntry.data.resize(debugEntry.idd.SizeOfData);
			inStream.seekg(debugEntry.idd.PointerToRawData);
			inStream.read(reinterpret_cast<char*>(debugEntry.data.data()), debugEntry.idd.SizeOfData);

			// Verify the number of bytes read
			if(inStream.gcount() != debugEntry.idd.SizeOfData)
				return ERROR_INVALID_FILE;

			if (debugEntry.idd.SizeOfData > 0)
			{
				m_occupiedAddresses.push_back(
					std::make_pair(
					debugEntry.idd.AddressOfRawData,
					debugEntry.idd.AddressOfRawData + debugEntry.idd.SizeOfData - 1
				));
			}
		}

		std::swap(debugInfo, m_vDebugInfo);
		return ERROR_NONE;
	}

	void DebugDirectory::read(ImageLoader & imageLoader,
		                      std::vector<PELIB_IMG_DEBUG_DIRECTORY> & debugInfo,
		                      std::uint32_t rva,
		                      std::uint32_t size)
	{
		PELIB_IMG_DEBUG_DIRECTORY iddCurr;
		std::size_t entryCount = size / PELIB_IMAGE_DEBUG_DIRECTORY::size();
		std::uint32_t bytesRead;

		for (std::size_t i = 0; i < entryCount; i++)
		{
			bytesRead = imageLoader.readImage(&iddCurr.idd, rva, sizeof(PELIB_IMAGE_DEBUG_DIRECTORY));
			if(bytesRead != sizeof(PELIB_IMAGE_DEBUG_DIRECTORY))
				break;

			debugInfo.push_back(iddCurr);
			rva += sizeof(PELIB_IMAGE_DEBUG_DIRECTORY);
		}

		if (!debugInfo.empty())
		{
			m_occupiedAddresses.emplace_back(
						rva,
						rva + entryCount * PELIB_IMAGE_DEBUG_DIRECTORY::size() - 1
					);
		}
	}

	/**
	* Rebuilds the current debug directory.
	* @param vBuffer Buffer where the rebuilt directory is stored.
	**/
	void DebugDirectory::rebuild(std::vector<std::uint8_t>& vBuffer) const
	{
		OutputBuffer obBuffer(vBuffer);

		for (unsigned int i=0;i<m_vDebugInfo.size();i++)
		{
			obBuffer << m_vDebugInfo[i].idd.Characteristics;
			obBuffer << m_vDebugInfo[i].idd.TimeDateStamp;
			obBuffer << m_vDebugInfo[i].idd.MajorVersion;
			obBuffer << m_vDebugInfo[i].idd.MinorVersion;
			obBuffer << m_vDebugInfo[i].idd.Type;
			obBuffer << m_vDebugInfo[i].idd.SizeOfData;
			obBuffer << m_vDebugInfo[i].idd.AddressOfRawData;
			obBuffer << m_vDebugInfo[i].idd.PointerToRawData;
		}
	}

	/**
	* @return Size of the debug directory.
	**/
	unsigned int DebugDirectory::size() const
	{
		return static_cast<unsigned int>(m_vDebugInfo.size()) * PELIB_IMAGE_DEBUG_DIRECTORY::size();
	}

	/**
	* @param strFilename Name of the file which will be written.
	* @param uiOffset File offset where the debug directory will be stored.
	**/
	int DebugDirectory::write(const std::string& strFilename, unsigned int uiOffset) const
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
	* @return Number of debug structures in the current Debug directory.
	**/
	unsigned int DebugDirectory::calcNumberOfEntries() const
	{
		return static_cast<unsigned int>(m_vDebugInfo.size());
	}

	/**
	* Adds a new debug structure to the debug directory. The initial values of all members of the structure
	* are undefined.
	**/
	void DebugDirectory::addEntry()
	{
		PELIB_IMG_DEBUG_DIRECTORY p;
		m_vDebugInfo.push_back(p);
	}

	/**
	* Removes a debug structure from the current debug directory. If an invalid structure is specified
	* by the parameter uiIndex the result will be undefined behaviour.
	* @param uiIndex Identifies the debug structure.
	**/
	void DebugDirectory::removeEntry(std::size_t uiIndex)
	{
		m_vDebugInfo.erase(m_vDebugInfo.begin() + uiIndex);
	}

	/**
	* Returns the Characteristics value of a debug structure. If an invalid structure is specified
	* by the parameter uiIndex the result will be undefined behaviour.
	* @param uiIndex Identifies the debug structure.
	* @return Characteristics value of the debug structure.
	**/
	std::uint32_t DebugDirectory::getCharacteristics(std::size_t uiIndex) const
	{
		return m_vDebugInfo[uiIndex].idd.Characteristics;
	}

	/**
	* Returns the TimeDateStamp value of a debug structure. If an invalid structure is specified
	* by the parameter uiIndex the result will be undefined behaviour.
	* @param uiIndex Identifies the debug structure.
	* @return TimeDateStamp value of the debug structure.
	**/
	std::uint32_t DebugDirectory::getTimeDateStamp(std::size_t uiIndex) const
	{
		return m_vDebugInfo[uiIndex].idd.TimeDateStamp;
	}

	/**
	* Returns the MajorVersion value of a debug structure. If an invalid structure is specified
	* by the parameter uiIndex the result will be undefined behaviour.
	* @param uiIndex Identifies the debug structure.
	* @return MajorVersion value of the debug structure.
	**/
	std::uint16_t DebugDirectory::getMajorVersion(std::size_t uiIndex) const
	{
		return m_vDebugInfo[uiIndex].idd.MajorVersion;
	}

	/**
	* Returns the MinorVersion value of a debug structure. If an invalid structure is specified
	* by the parameter uiIndex the result will be undefined behaviour.
	* @param uiIndex Identifies the debug structure.
	* @return MinorVersion value of the debug structure.
	**/
	std::uint16_t DebugDirectory::getMinorVersion(std::size_t uiIndex) const
	{
		return m_vDebugInfo[uiIndex].idd.MinorVersion;
	}

	/**
	* Returns the Type value of a debug structure. If an invalid structure is specified
	* by the parameter uiIndex the result will be undefined behaviour.
	* @param uiIndex Identifies the debug structure.
	* @return Type value of the debug structure.
	**/
	std::uint32_t DebugDirectory::getType(std::size_t uiIndex) const
	{
		return m_vDebugInfo[uiIndex].idd.Type;
	}

	/**
	* Returns the SizeOfData value of a debug structure. If an invalid structure is specified
	* by the parameter uiIndex the result will be undefined behaviour.
	* @param uiIndex Identifies the debug structure.
	* @return SizeOfData value of the debug structure.
	**/
	std::uint32_t DebugDirectory::getSizeOfData(std::size_t uiIndex) const
	{
		return m_vDebugInfo[uiIndex].idd.SizeOfData;
	}

	/**
	* Returns the AddressOfRawData value of a debug structure. If an invalid structure is specified
	* by the parameter uiIndex the result will be undefined behaviour.
	* @param uiIndex Identifies the debug structure.
	* @return AddressOfRawData value of the debug structure.
	**/
	std::uint32_t DebugDirectory::getAddressOfRawData(std::size_t uiIndex) const
	{
		return m_vDebugInfo[uiIndex].idd.AddressOfRawData;
	}

	/**
	* Returns the PointerToRawData value of a debug structure. If an invalid structure is specified
	* by the parameter uiIndex the result will be undefined behaviour.
	* @param uiIndex Identifies the debug structure.
	* @return PointerToRawData value of the debug structure.
	**/
	std::uint32_t DebugDirectory::getPointerToRawData(std::size_t uiIndex) const
	{
		return m_vDebugInfo[uiIndex].idd.PointerToRawData;
	}

	std::vector<std::uint8_t> DebugDirectory::getData(std::size_t index) const
	{
		return m_vDebugInfo[index].data;
	}

	/**
	* Changes the Characteristics value of a debug structure. If an invalid structure is specified
	* by the parameter uiIndex the result will be undefined behaviour.
	* @param uiIndex Identifies the debug structure.
	* @param dwValue New value of the Characteristics value of the debug structure.
	**/
	void DebugDirectory::setCharacteristics(std::size_t uiIndex, std::uint32_t dwValue)
	{
		m_vDebugInfo[uiIndex].idd.Characteristics = dwValue;
	}

	/**
	* Changes the TimeDateStamp value of a debug structure. If an invalid structure is specified
	* by the parameter uiIndex the result will be undefined behaviour.
	* @param uiIndex Identifies the debug structure.
	* @param dwValue New value of the TimeDateStamp value of the debug structure.
	**/
	void DebugDirectory::setTimeDateStamp(std::size_t uiIndex, std::uint32_t dwValue)
	{
		m_vDebugInfo[uiIndex].idd.TimeDateStamp = dwValue;
	}

	/**
	* Changes the MajorVersion value of a debug structure. If an invalid structure is specified
	* by the parameter uiIndex the result will be undefined behaviour.
	* @param uiIndex Identifies the debug structure.
	* @param wValue New value of the MajorVersion value of the debug structure.
	**/
	void DebugDirectory::setMajorVersion(std::size_t uiIndex, std::uint16_t wValue)
	{
		m_vDebugInfo[uiIndex].idd.MajorVersion = wValue;
	}

	/**
	* Changes the MinorVersion value of a debug structure. If an invalid structure is specified
	* by the parameter uiIndex the result will be undefined behaviour.
	* @param uiIndex Identifies the debug structure.
	* @param wValue New value of the MinorVersion value of the debug structure.
	**/
	void DebugDirectory::setMinorVersion(std::size_t uiIndex, std::uint16_t wValue)
	{
		m_vDebugInfo[uiIndex].idd.MinorVersion = wValue;
	}

	/**
	* Changes the Type value of a debug structure. If an invalid structure is specified
	* by the parameter uiIndex the result will be undefined behaviour.
	* @param uiIndex Identifies the debug structure.
	* @param dwValue New value of the Type value of the debug structure.
	**/
	void DebugDirectory::setType(std::size_t uiIndex, std::uint32_t dwValue)
	{
		m_vDebugInfo[uiIndex].idd.Type = dwValue;
	}

	/**
	* Changes the SizeOfData value of a debug structure. If an invalid structure is specified
	* by the parameter uiIndex the result will be undefined behaviour.
	* @param uiIndex Identifies the debug structure.
	* @param dwValue New value of the SizeOfData value of the debug structure.
	**/
	void DebugDirectory::setSizeOfData(std::size_t uiIndex, std::uint32_t dwValue)
	{
		m_vDebugInfo[uiIndex].idd.SizeOfData = dwValue;
	}

	/**
	* Changes the AddressOfRawData value of a debug structure. If an invalid structure is specified
	* by the parameter uiIndex the result will be undefined behaviour.
	* @param uiIndex Identifies the debug structure.
	* @param dwValue New value of the AddressOfRawData value of the debug structure.
	**/
	void DebugDirectory::setAddressOfRawData(std::size_t uiIndex, std::uint32_t dwValue)
	{
		m_vDebugInfo[uiIndex].idd.AddressOfRawData = dwValue;
	}

	/**
	* Changes the PointerToRawData value of a debug structure. If an invalid structure is specified
	* by the parameter uiIndex the result will be undefined behaviour.
	* @param uiIndex Identifies the debug structure.
	* @param dwValue New value of the PointerToRawData value of the debug structure.
	**/
	void DebugDirectory::setPointerToRawData(std::size_t uiIndex, std::uint32_t dwValue)
	{
		m_vDebugInfo[uiIndex].idd.PointerToRawData = dwValue;
	}

	void DebugDirectory::setData(std::size_t index, const std::vector<std::uint8_t>& data)
	{
		m_vDebugInfo[index].data = data;
	}

	const std::vector<std::pair<unsigned int, unsigned int>>& DebugDirectory::getOccupiedAddresses() const
	{
		return m_occupiedAddresses;
	}
}
