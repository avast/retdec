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

#include "retdec/pelib/IatDirectory.h"

namespace PeLib
{
	/**
	* Reads the Import Address table from an image
	* @param buffer Pointer to the IAT data
	* @param buffersize Length of the data pointed by 'buffer'
	**/
	int IatDirectory::read(const void * buffer, std::size_t buffersize)
	{
		const std::uint32_t * itemArray = reinterpret_cast<const std::uint32_t *>(buffer);

		// Resize the IAT vector to contain all items
		std::size_t itemCount = buffersize / sizeof(std::uint32_t);
		m_vIat.clear();

		// Read the items, one-by-one, until we find a zero value
		for(std::size_t i = 0; i < itemCount; i++)
		{
			// Insert that item
			m_vIat.push_back(itemArray[i]);

			// Zero is considered terminator
			if(itemArray[i] == 0)
				break;
		}

		return ERROR_NONE;
	}

	/**
	* Reads the Import Address table from an image
	* @param imageLoader Initialized image loader
	**/
	int IatDirectory::read(ImageLoader & imageLoader)
	{
		std::uint8_t * iatArray;
		std::uint32_t iatRva = imageLoader.getDataDirRva(PELIB_IMAGE_DIRECTORY_ENTRY_IAT);
		std::uint32_t iatSize = imageLoader.getDataDirSize(PELIB_IMAGE_DIRECTORY_ENTRY_IAT);
		std::uint32_t sizeOfImage = imageLoader.getSizeOfImage();
		int fileError = ERROR_NONE;

		// Refuse to load blatantly invalid IAT
		if(iatSize & 0xFF000000)
			return ERROR_INVALID_FILE;

		// Refuse to load too large IAT directories
		if((iatRva + iatSize) < iatRva || iatRva >= sizeOfImage || (iatRva + iatSize) >= sizeOfImage)
			return ERROR_INVALID_FILE;

		// Trim the array size to the size of image
		if((iatRva + iatSize) > sizeOfImage)
			iatSize = sizeOfImage - iatRva;

		// Allocate array for the entire IAT
		if((iatArray = new std::uint8_t[iatSize]) != nullptr)
		{
			// Read the entire IAT to the memory
			iatSize = imageLoader.readImage(iatArray, iatRva, iatSize);

			// Insert the IAT array to the internal IAT vector
			fileError = read(iatArray, iatSize);
			delete [] iatArray;
		}
		else
		{
			fileError = ERROR_NOT_ENOUGH_SPACE;
		}

		return fileError;
	}

	/**
	* Returns the number of fields in the IAT. This is equivalent to the number of
	* imported functions.
	* @return Number of fields in the IAT.
	**/
	unsigned int IatDirectory::calcNumberOfAddresses() const
	{
		return static_cast<unsigned int>(m_vIat.size());
	}

	/**
	* Returns the dwValue of a field in the IAT.
	* @param index Number identifying the field.
	* @return dwValue of the field.
	**/
	std::uint32_t IatDirectory::getAddress(unsigned int index) const
	{
		return m_vIat[index];
	}

	/**
	* Updates the dwValue of a field in the IAT.
	* @param dwAddrnr Number identifying the field.
	* @param dwValue New dwValue of the field.
	**/
	void IatDirectory::setAddress(std::uint32_t dwAddrnr, std::uint32_t dwValue)
	{
		m_vIat[dwAddrnr] = dwValue;
	}

	/**
	* Adds another field to the IAT.
	* @param dwValue dwValue of the new field.
	**/
	void IatDirectory::addAddress(std::uint32_t dwValue)
	{
		m_vIat.push_back(dwValue);
	}

	/**
	* Removes an address from the IAT.
	* @param index Number identifying the field.
	**/
	void IatDirectory::removeAddress(unsigned int index)
	{
		std::vector<std::uint32_t>::iterator pos = m_vIat.begin() + index;
		m_vIat.erase(pos);
	}

	/**
	* Delete all entries from the IAT.
	**/
	void IatDirectory::clear()
	{
		m_vIat.clear();
	}

	/**
	* Rebuilds the complete Import Address Table.
	* @param vBuffer Buffer where the rebuilt IAT will be stored.
	**/
	void IatDirectory::rebuild(std::vector<std::uint8_t>& vBuffer) const
	{
		vBuffer.resize(size());
		OutputBuffer obBuffer(vBuffer);

		for (unsigned int i=0;i<m_vIat.size();i++)
		{
			obBuffer << m_vIat[i];
		}
	}

	unsigned int IatDirectory::size() const
	{
		return static_cast<unsigned int>(m_vIat.size())* sizeof(std::uint32_t);
	}

	/// Writes the current IAT to a file.
	int IatDirectory::write(const std::string& strFilename, unsigned int uiOffset) const
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
}
