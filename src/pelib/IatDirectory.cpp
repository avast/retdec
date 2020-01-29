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

#include "pelib/IatDirectory.h"

namespace PeLib
{
	int IatDirectory::read(InputBuffer& inputBuffer, unsigned int dwOffset, unsigned int dwFileSize)
	{
		dword dwAddr;

		std::vector<dword> vIat;

		unsigned int dwCurrentOffset = dwOffset;
		while (dwCurrentOffset < dwFileSize)
		{
			inputBuffer >> dwAddr;
			if (dwAddr == 0)
				break;

			vIat.push_back(dwAddr);
			dwCurrentOffset += sizeof(dwAddr);
		}

		std::swap(vIat, m_vIat);

		return ERROR_NONE;
	}

	int IatDirectory::read(unsigned char* buffer, unsigned int buffersize)
	{
		std::vector<byte> vBuffer(buffer, buffer + buffersize);
		InputBuffer inpBuffer(vBuffer);
		return read(inpBuffer, 0, buffersize);
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
	* @param dwAddrnr Number identifying the field.
	* @return dwValue of the field.
	**/
	dword IatDirectory::getAddress(unsigned int index) const
	{
		return m_vIat[index];
	}

	/**
	* Updates the dwValue of a field in the IAT.
	* @param dwAddrnr Number identifying the field.
	* @param dwValue New dwValue of the field.
	**/
	void IatDirectory::setAddress(dword dwAddrnr, dword dwValue)
	{
		m_vIat[dwAddrnr] = dwValue;
	}

	/**
	* Adds another field to the IAT.
	* @param dwValue dwValue of the new field.
	**/
	void IatDirectory::addAddress(dword dwValue)
	{
		m_vIat.push_back(dwValue);
	}

	/**
	* Removes an address from the IAT.
	* @param dwAddrnr Number identifying the field.
	**/
	void IatDirectory::removeAddress(unsigned int index)
	{
		std::vector<dword>::iterator pos = m_vIat.begin() + index;
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
	void IatDirectory::rebuild(std::vector<byte>& vBuffer) const
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
		return static_cast<unsigned int>(m_vIat.size())* sizeof(dword);
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
