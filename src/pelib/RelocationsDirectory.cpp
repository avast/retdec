/*
* Relocations.cpp - Part of the PeLib library.
*
* Copyright (c) 2004 - 2005 Sebastian Porst (webmaster@the-interweb.com)
* All rights reserved.
*
* This software is licensed under the zlib/libpng License.
* For more details see http://www.opensource.org/licenses/zlib-license.php
* or the license information file (license.htm) in the root directory
* of PeLib.
*/

#include "pelib/PeLibInc.h"
#include "pelib/RelocationsDirectory.h"

namespace PeLib
{
	void RelocationsDirectory::setRelocationData(unsigned int ulRelocation, unsigned int ulDataNumber, word wData)
	{
		m_vRelocations[ulRelocation].vRelocData[ulDataNumber] = wData;
	}

	void RelocationsDirectory::read(InputBuffer& inputbuffer, unsigned int uiSize)
	{
		IMG_BASE_RELOC ibrCurr;

		std::vector<IMG_BASE_RELOC> vCurrReloc;

		do
		{
			if (inputbuffer.get() + sizeof(ibrCurr.ibrRelocation.VirtualAddress) + sizeof(ibrCurr.ibrRelocation.SizeOfBlock) > uiSize)
			{
				break;
			}
			inputbuffer >> ibrCurr.ibrRelocation.VirtualAddress;
			inputbuffer >> ibrCurr.ibrRelocation.SizeOfBlock;

			ibrCurr.vRelocData.clear();

			// That's not how to check if there are relocations, some DLLs start at VA 0.
			// if (!ibrCurr.ibrRelocation.VirtualAddress) break;

			for (unsigned int i=0;i<(ibrCurr.ibrRelocation.SizeOfBlock - PELIB_IMAGE_SIZEOF_BASE_RELOCATION) / sizeof(word);i++)
			{
				if (inputbuffer.get() + sizeof(word) > uiSize)
				{
					break;
				}
				word wData;
				inputbuffer >> wData;
				ibrCurr.vRelocData.push_back(wData);
			}

			vCurrReloc.push_back(ibrCurr);
		} while (ibrCurr.ibrRelocation.VirtualAddress && inputbuffer.get() < uiSize);

		std::swap(vCurrReloc, m_vRelocations);
	}

	// TODO: Return value is wrong if buffer was too small.
	int RelocationsDirectory::read(const unsigned char* buffer, unsigned int buffersize)
	{
		std::vector<unsigned char> vRelocDirectory(buffer, buffer + buffersize);

		InputBuffer ibBuffer(vRelocDirectory);
		read(ibBuffer, buffersize);

		return ERROR_NONE;
	}

	unsigned int RelocationsDirectory::size() const
	{
		unsigned int size2 = static_cast<unsigned int>(m_vRelocations.size()) * PELIB_IMAGE_BASE_RELOCATION::size();

		for (unsigned int i=0;i<m_vRelocations.size();i++)
		{
			size2 += static_cast<unsigned int>(m_vRelocations[i].vRelocData.size()) * sizeof(word);
		}

		return size2;
	}

	unsigned int RelocationsDirectory::calcNumberOfRelocations() const
	{
		return static_cast<unsigned int>(m_vRelocations.size());
	}

	dword RelocationsDirectory::getVirtualAddress(unsigned int ulRelocation) const
	{
		return m_vRelocations[ulRelocation].ibrRelocation.VirtualAddress;
	}

	dword RelocationsDirectory::getSizeOfBlock(unsigned int ulRelocation) const
	{
		return m_vRelocations[ulRelocation].ibrRelocation.SizeOfBlock;
	}

	unsigned int RelocationsDirectory::calcNumberOfRelocationData(unsigned int ulRelocation) const
	{
		return static_cast<unsigned int>(m_vRelocations[ulRelocation].vRelocData.size());
	}

	word RelocationsDirectory::getRelocationData(unsigned int ulRelocation, unsigned int ulDataNumber) const
	{
		return m_vRelocations[ulRelocation].vRelocData[ulDataNumber];
	}

	void RelocationsDirectory::setVirtualAddress(unsigned int ulRelocation, dword dwValue)
	{
		m_vRelocations[ulRelocation].ibrRelocation.VirtualAddress = dwValue;
	}

	void RelocationsDirectory::setSizeOfBlock(unsigned int ulRelocation, dword dwValue)
	{
		m_vRelocations[ulRelocation].ibrRelocation.SizeOfBlock = dwValue;
	}

	void RelocationsDirectory::addRelocation()
	{
		IMG_BASE_RELOC newrelocation;
		m_vRelocations.push_back(newrelocation);
	}

	void RelocationsDirectory::addRelocationData(unsigned int ulRelocation, word wValue)
	{
		m_vRelocations[ulRelocation].vRelocData.push_back(wValue);
	}

/*	void RelocationsDirectory::removeRelocationData(unsigned int ulRelocation, word wValue)
	{
		// If you get an error with Borland C++ here you have two options: Upgrade your compiler
		// or use the commented line instead of the line below.
		m_vRelocations[ulRelocation].vRelocData.erase(std::remove(m_vRelocations[ulRelocation].vRelocData.begin(), m_vRelocations[ulRelocation].vRelocData.end(), wValue), m_vRelocations[ulRelocation].vRelocData.end());
	}
*/
	void RelocationsDirectory::removeRelocation(unsigned int index)
	{
		m_vRelocations.erase(m_vRelocations.begin() + index);
	}

	void RelocationsDirectory::removeRelocationData(unsigned int relocindex, unsigned int dataindex)
	{
		m_vRelocations[relocindex].vRelocData.erase(m_vRelocations[relocindex].vRelocData.begin() + dataindex);
	}
}
