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

#include "retdec/pelib/PeLibInc.h"
#include "retdec/pelib/RelocationsDirectory.h"

namespace PeLib
{
	/**
	* Constructor
	*/
	RelocationsDirectory::RelocationsDirectory() : m_ldrError(LDR_ERROR_NONE)
	{}

	int RelocationsDirectory::read(ImageLoader & imageLoader)
	{
		std::uint32_t rva = imageLoader.getDataDirRva(PELIB_IMAGE_DIRECTORY_ENTRY_BASERELOC);
		std::uint32_t size = imageLoader.getDataDirSize(PELIB_IMAGE_DIRECTORY_ENTRY_BASERELOC);
		std::uint32_t sizeOfImage = imageLoader.getSizeOfImage();
		std::uint64_t sizeOfFile = imageLoader.getSizeOfFile();

		// Check for relocations out of image
		if(rva >= sizeOfImage || (rva + size) < rva || (rva + size) > sizeOfImage)
		{
			RelocationsDirectory::setLoaderError(LDR_ERROR_RELOCATIONS_OUT_OF_IMAGE);
			return ERROR_INVALID_FILE;
		}

		// Check for relocations out of file
		if(size > sizeOfFile)
		{
			RelocationsDirectory::setLoaderError(LDR_ERROR_RELOCATIONS_OUT_OF_IMAGE);
			return ERROR_INVALID_FILE;
		}

		// Read the entire relocation directory from the image
		std::vector<std::uint8_t> vRelocDirectory(size);
		if(imageLoader.readImage(vRelocDirectory.data(), rva, size) != size)
			return ERROR_INVALID_FILE;

		// Parse the relocations directory
		read(vRelocDirectory.data(), size, sizeOfImage);
		return ERROR_NONE;
	}

	/**
	* Get the error that was detected during parsing of relocations
	**/
	LoaderError RelocationsDirectory::loaderError() const
	{
		return m_ldrError;
	}

	void RelocationsDirectory::setLoaderError(LoaderError ldrError)
	{
		// Do not override an existing error
		if (m_ldrError == LDR_ERROR_NONE)
		{
			m_ldrError = ldrError;
		}
	}

	void RelocationsDirectory::setRelocationData(unsigned int ulRelocation, unsigned int ulDataNumber, std::uint16_t wData)
	{
		m_vRelocations[ulRelocation].vRelocData[ulDataNumber] = wData;
	}

	void RelocationsDirectory::read(const std::uint8_t * data, std::uint32_t uiSize, std::uint32_t sizeOfImage)
	{
		const std::uint8_t * dataEnd = data + uiSize;

		// Clear the current relocations
		m_vRelocations.clear();

		// The entire relocation block looks like this:
		// * PELIB_IMAGE_BASE_RELOCATION (header of block)
		// * array of relocation entry, each has 2 bytes
		// * PELIB_IMAGE_BASE_RELOCATION (header of next block)
		// * array of relocation entry, each has 2 bytes
		// ... and so on, up to uiSize
		while((data + PELIB_IMAGE_SIZEOF_BASE_RELOCATION) < dataEnd)
		{
			const PELIB_IMAGE_BASE_RELOCATION * pRelocBlock = (const PELIB_IMAGE_BASE_RELOCATION *)data;
			IMG_BASE_RELOC ibrCurr;

			// Retrieve the single PELIB_IMAGE_BASE_RELOCATION entry.
			// Note that SizeOfBlock contains size of PELIB_IMAGE_BASE_RELOCATION itself
			// plus sizes of all subsequent fixup entries
			ibrCurr.ibrRelocation.VirtualAddress = pRelocBlock->VirtualAddress;
			ibrCurr.ibrRelocation.SizeOfBlock = pRelocBlock->SizeOfBlock;

			// Verify whether the base virtual address is within the image
			if(ibrCurr.ibrRelocation.VirtualAddress > sizeOfImage)
			{
				setLoaderError(LDR_ERROR_RELOC_BLOCK_INVALID_VA);
				break;
			}
			if((data + ibrCurr.ibrRelocation.SizeOfBlock) > dataEnd)
			{
				setLoaderError(LDR_ERROR_RELOC_BLOCK_INVALID_LENGTH);
				break;
			}

			// Move the offset by the size of relocation block structure
			data += PELIB_IMAGE_SIZEOF_BASE_RELOCATION;

			// Prevent underflow caused by size smaller than PELIB_IMAGE_SIZEOF_BASE_RELOCATION.
			// Example: \retdec-regression-tests\tools\fileinfo\detection\packers\securom\sample_securom_003.dat
			if(ibrCurr.ibrRelocation.SizeOfBlock >= PELIB_IMAGE_SIZEOF_BASE_RELOCATION)
			{
				// Get the number of fixup entries
				const std::uint16_t * typeAndOffsets = (const std::uint16_t *)(pRelocBlock + 1);
				std::uint32_t numberOfEntries = (ibrCurr.ibrRelocation.SizeOfBlock - PELIB_IMAGE_SIZEOF_BASE_RELOCATION) / sizeof(uint16_t);

				for (std::uint32_t i = 0; i < numberOfEntries; i++)
				{
					// Read the type and offset
					if((data + sizeof(std::uint16_t)) > dataEnd)
						break;
					uint16_t typeAndOffset = typeAndOffsets[i];

					// Verify the type and offset
					switch(typeAndOffset >> 12)
					{
						case PELIB_IMAGE_REL_BASED_HIGHADJ:	// This relocation entry occupies two entries
							data += sizeof(uint16_t);
							// No break here!

						case PELIB_IMAGE_REL_BASED_ABSOLUTE:
						case PELIB_IMAGE_REL_BASED_HIGH:
						case PELIB_IMAGE_REL_BASED_LOW:
						case PELIB_IMAGE_REL_BASED_HIGHLOW:
						case PELIB_IMAGE_REL_BASED_MIPS_JMPADDR:
						case PELIB_IMAGE_REL_BASED_IA64_IMM64:
						case PELIB_IMAGE_REL_BASED_DIR64:

							// This is a correct relocation entry. Lower 12 bits contains
							// relocation offset relative to ibrCurr.ibrRelocation.VirtualAddress
							break;

						default:    // Invalid relocation entry type
							setLoaderError(LDR_ERROR_RELOC_ENTRY_BAD_TYPE);
							break;
					}

					// Push the relocation entry to the list
					ibrCurr.vRelocData.push_back(typeAndOffset);
					data += sizeof(uint16_t);
				}

				// Push the data to the relocations vector
				m_vRelocations.push_back(std::move(ibrCurr));
			}
		}
	}

	unsigned int RelocationsDirectory::size() const
	{
		unsigned int size2 = static_cast<unsigned int>(m_vRelocations.size()) * PELIB_IMAGE_BASE_RELOCATION::size();

		for (unsigned int i=0;i<m_vRelocations.size();i++)
		{
			size2 += static_cast<unsigned int>(m_vRelocations[i].vRelocData.size()) * sizeof(std::uint16_t);
		}

		return size2;
	}

	unsigned int RelocationsDirectory::calcNumberOfRelocations() const
	{
		return static_cast<unsigned int>(m_vRelocations.size());
	}

	std::uint32_t RelocationsDirectory::getVirtualAddress(unsigned int ulRelocation) const
	{
		return m_vRelocations[ulRelocation].ibrRelocation.VirtualAddress;
	}

	std::uint32_t RelocationsDirectory::getSizeOfBlock(unsigned int ulRelocation) const
	{
		return m_vRelocations[ulRelocation].ibrRelocation.SizeOfBlock;
	}

	unsigned int RelocationsDirectory::calcNumberOfRelocationData(unsigned int ulRelocation) const
	{
		return static_cast<unsigned int>(m_vRelocations[ulRelocation].vRelocData.size());
	}

	std::uint16_t RelocationsDirectory::getRelocationData(unsigned int ulRelocation, unsigned int ulDataNumber) const
	{
		return m_vRelocations[ulRelocation].vRelocData[ulDataNumber];
	}

	void RelocationsDirectory::setVirtualAddress(unsigned int ulRelocation, std::uint32_t dwValue)
	{
		m_vRelocations[ulRelocation].ibrRelocation.VirtualAddress = dwValue;
	}

	void RelocationsDirectory::setSizeOfBlock(unsigned int ulRelocation, std::uint32_t dwValue)
	{
		m_vRelocations[ulRelocation].ibrRelocation.SizeOfBlock = dwValue;
	}

	void RelocationsDirectory::addRelocation()
	{
		IMG_BASE_RELOC newrelocation;
		m_vRelocations.push_back(newrelocation);
	}

	void RelocationsDirectory::addRelocationData(unsigned int ulRelocation, std::uint16_t wValue)
	{
		m_vRelocations[ulRelocation].vRelocData.push_back(wValue);
	}

/*	void RelocationsDirectory::removeRelocationData(unsigned int ulRelocation, std::uint16_t wValue)
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
