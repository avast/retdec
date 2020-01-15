/*
* MzHeader.cpp - Part of the PeLib library.
*
* Copyright (c) 2004 - 2005 Sebastian Porst (webmaster@the-interweb.com)
* All rights reserved.
*
* This software is licensed under the zlib/libpng License.
* For more details see http://www.opensource.org/licenses/zlib-license.php
* or the license information file (license.htm) in the root directory
* of PeLib.
*/

#include <iostream>

#include "pelib/MzHeader.h"

namespace PeLib
{
	/**
	* Reads data from an InputBuffer into the struct that represents the MZ header.
	* It's required that the size of the input buffer is at least as big as the
	* size of a MZ header. Otherwise we get undefined behaviour.
	* @param ibBuffer InputBuffer that holds the data.
	* @return A non-zero value is returned if a problem occured.
	**/
	void MzHeader::read(InputBuffer& ibBuffer)
	{
		ibBuffer >> m_idhHeader.e_magic;
		ibBuffer >> m_idhHeader.e_cblp;
		ibBuffer >> m_idhHeader.e_cp;
		ibBuffer >> m_idhHeader.e_crlc;
		ibBuffer >> m_idhHeader.e_cparhdr;
		ibBuffer >> m_idhHeader.e_minalloc;
		ibBuffer >> m_idhHeader.e_maxalloc;
		ibBuffer >> m_idhHeader.e_ss;
		ibBuffer >> m_idhHeader.e_sp;
		ibBuffer >> m_idhHeader.e_csum;
		ibBuffer >> m_idhHeader.e_ip;
		ibBuffer >> m_idhHeader.e_cs;
		ibBuffer >> m_idhHeader.e_lfarlc;
		ibBuffer >> m_idhHeader.e_ovno;

		for (unsigned int i=0;i<sizeof(m_idhHeader.e_res)/sizeof(m_idhHeader.e_res[0]);i++)
		{
			ibBuffer >> m_idhHeader.e_res[i];
		}

		ibBuffer >> m_idhHeader.e_oemid;
		ibBuffer >> m_idhHeader.e_oeminfo;

		for (unsigned int i=0;i<sizeof(m_idhHeader.e_res2)/sizeof(m_idhHeader.e_res2[0]);i++)
		{
			ibBuffer >> m_idhHeader.e_res2[i];
		}

		ibBuffer >> m_idhHeader.e_lfanew;
	}

	MzHeader::MzHeader(): originalOffset(0), m_ldrError() {}

	/**
	* Tests if the currently loaded MZ header is a valid MZ header.
	* Note that this function does not check if the address to the PE header is valid as this is not possible.
	* Actually, the only thing this function checks is if the e_magic value is set to 0x5A4D (IMAGE_DOS_SIGNATURE).
	* Everything else is not relevant for Windows 2000 and that's the system PeLib is focusing on for now.
	* @return A boolean value that indicates if the MZ header is correct or not.
	**/
	bool MzHeader::isValid() const
	{
		// The only thing that matters on Windows 2K is the e_magic value. The entire rest is for DOS compatibility.
		return isValid(e_magic);
	}

	bool MzHeader::isValid(Field f) const
	{
		if (f == e_magic)
		{
			return m_idhHeader.e_magic == PELIB_IMAGE_DOS_SIGNATURE;
		}
		else
		{
			return true;
		}
	}

	void MzHeader::setLoaderError(LoaderError ldrError)
	{
		// Do not override an existing loader error
		if (m_ldrError == LDR_ERROR_NONE)
		{
			m_ldrError = ldrError;
		}
	}

	LoaderError MzHeader::loaderError() const
	{
		return m_ldrError;
	}

	/**
	* Corrects all erroneous values of the current MZ header. Note that this function does not correct the
	* pointer to the PE header.
	* Actually, the only thing this function corrects is the e_magic value.
	* Everything else is not relevant for Windows 2000 and that's the system PeLib is focusing on for now.
	**/
	void MzHeader::makeValid()
	{
		// The only thing that matters on Windows is the e_magic value. The entire rest is for DOS compatibility.
		setMagicNumber(PELIB_IMAGE_DOS_SIGNATURE);
	}

	void MzHeader::makeValid(Field f)
	{
		if (f == e_magic)
		{
			setMagicNumber(PELIB_IMAGE_DOS_SIGNATURE);
		}
	}

	/**
	* Reads the MZ header from a file. Note that this function does not verify if a file is actually a MZ file.
	* For this purpose see #PeFile::MzHeader::isValid. The reason for this is simple: Otherwise it might not
	* be possible to load damaged PE files to repair them.
	* @param inStream Input stream.
	* @return A non-zero value is returned if a problem occured.
	**/
	int MzHeader::read(std::istream& inStream)
	{
		IStreamWrapper inStream_w(inStream);

		if (!inStream_w)
		{
			return ERROR_OPENING_FILE;
		}

		std::uint64_t ulFileSize = fileSize(inStream_w);
		if (ulFileSize < PELIB_IMAGE_DOS_HEADER::size())
		{
			return ERROR_INVALID_FILE;
		}

		// Windows loader refuses to load any file which is larger than 0xFFFFFFFF
		if ((ulFileSize >> 32) != 0)
		{
			setLoaderError(LDR_ERROR_FILE_TOO_BIG);
		}

		inStream_w.seekg(0, std::ios::beg);

		originalOffset = 0;

		std::vector<byte> vBuffer(PELIB_IMAGE_DOS_HEADER::size());
		inStream_w.read(reinterpret_cast<char*>(vBuffer.data()), static_cast<unsigned int>(vBuffer.size()));
		inStream_w.seekg(0, std::ios::beg);
		m_headerString.clear();
		m_headerString.resize(PELIB_IMAGE_DOS_HEADER::size());
		inStream_w.read(&m_headerString[0], PELIB_IMAGE_DOS_HEADER::size());

		InputBuffer ibBuffer(vBuffer);
		read(ibBuffer);

		// For 64-bit systems, the e_lfanew must be aligned to 4
		if (m_idhHeader.e_lfanew & 3)
			setLoaderError(LDR_ERROR_E_LFANEW_UNALIGNED);

		// The offset of PE header must not be out of file
		if (m_idhHeader.e_lfanew > (std::uint32_t)ulFileSize)
			setLoaderError(LDR_ERROR_E_LFANEW_OUT_OF_FILE);

		return ERROR_NONE;
	}

	/**
	* Reads the MZ header from memory. A pointer to a location in memory is passed and the data
	* at this location is treated like a MZ header structure. The MZ header does not need to be valid.
	* @param pcBuffer Pointer to a MZ header.
	* @param uiSize Length of the buffer.
	* @return A non-zero value is returned if a problem occured.
	**/
	int MzHeader::read(unsigned char* pcBuffer, unsigned int uiSize, unsigned int originalOffs)
	{
		if (uiSize < PELIB_IMAGE_DOS_HEADER::size())
		{
			return ERROR_INVALID_FILE;
		}

		std::vector<byte> vBuffer(pcBuffer, pcBuffer + uiSize);
		for (int i=0;i<0x40;i++) std::cout << std::hex << (int)vBuffer[i] << " ";

		originalOffset = originalOffs;

		InputBuffer ibBuffer(vBuffer);
		read(ibBuffer);
		return ERROR_NONE;
	}

	/**
	* Rebuilds the MZ header so that it can be written to a file. It's not guaranteed that the
	* MZ header will be valid. If you want to make sure that the MZ header will be valid you
	* must call #PeLib::MzHeader::makeValid first.
	* @param vBuffer Buffer where the rebuilt MZ header will be stored.
	**/
	void MzHeader::rebuild(std::vector<byte>& vBuffer) const
	{
		OutputBuffer obBuffer(vBuffer);

		obBuffer << m_idhHeader.e_magic;
		obBuffer << m_idhHeader.e_cblp;
		obBuffer << m_idhHeader.e_cp;
		obBuffer << m_idhHeader.e_crlc;
		obBuffer << m_idhHeader.e_cparhdr;
		obBuffer << m_idhHeader.e_minalloc;
		obBuffer << m_idhHeader.e_maxalloc;
		obBuffer << m_idhHeader.e_ss;
		obBuffer << m_idhHeader.e_sp;
		obBuffer << m_idhHeader.e_csum;
		obBuffer << m_idhHeader.e_ip;
		obBuffer << m_idhHeader.e_cs;
		obBuffer << m_idhHeader.e_lfarlc;
		obBuffer << m_idhHeader.e_ovno;

		for (unsigned int i=0;i<sizeof(m_idhHeader.e_res)/sizeof(m_idhHeader.e_res[0]);i++)
		{
			obBuffer << m_idhHeader.e_res[i];
		}

		obBuffer << m_idhHeader.e_oemid;
		obBuffer << m_idhHeader.e_oeminfo;

		for (unsigned int i=0;i<sizeof(m_idhHeader.e_res2)/sizeof(m_idhHeader.e_res2[0]);i++)
		{
			obBuffer << m_idhHeader.e_res2[i];
		}

		obBuffer << m_idhHeader.e_lfanew;
	}

	/**
	* Returns the size of the MZ header. This size is actually always sizeof(IMAGE_DOS_HEADER) (== 0x40)
	* because the MZ header is a header of constant size if you disregard the dos stub. If you want to know the
	* size of the MZ header + the size of the dos stub check #PeLib::MzHeader::getAddressOfPeHeader.
	* @return Size of the MZ header.
	**/
	unsigned int MzHeader::size() const
	{
		return sizeof(m_idhHeader);
	}

	/**
	* Writes the current MZ header to a file. The file does not have to exist. If it doesn't exist
	* it will be created.
	* @param strFilename Name of the file the header will be written to.
	* @param dwOffset Offset the header will be written to (defaults to 0).
	* @return A non-zero value is returned if a problem occured.
	**/
	int MzHeader::write(const std::string& strFilename, dword dwOffset = 0) const
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

		ofFile.seekp(dwOffset, std::ios::beg);

		std::vector<unsigned char> vBuffer;

		rebuild(vBuffer);

		ofFile.write(reinterpret_cast<const char*>(vBuffer.data()), static_cast<unsigned int>(vBuffer.size()));

		ofFile.close();

		return ERROR_NONE;
	}

	/**
	* Returns the MZ header.
	**/
	const PELIB_IMAGE_DOS_HEADER& MzHeader::getHeader() const
	{
		return m_idhHeader;
	}

	/**
	* Returns the MZ header in string representation.
	**/
	const std::string& MzHeader::getString() const
	{
		return m_headerString;
	}

	/**
	* Returns the MZ header's e_magic value.
	**/
	word MzHeader::getMagicNumber() const
	{
		return m_idhHeader.e_magic;
	}

	/**
	* Returns the MZ header's e_cblp value.
	**/
	word MzHeader::getBytesOnLastPage() const
	{
		return m_idhHeader.e_cblp;
	}

	/**
	* Returns the MZ header's e_cp value.
	**/
	word MzHeader::getPagesInFile() const
	{
		return m_idhHeader.e_cp;
	}

	/**
	* Returns the MZ header's e_crlc value.
	**/
	word MzHeader::getRelocations() const
	{
		return m_idhHeader.e_crlc;
	}

	/**
	* Returns the MZ header's e_cparhdr value.
	**/
	word MzHeader::getSizeOfHeader() const
	{
		return m_idhHeader.e_cparhdr;
	}

	/**
	* Returns the MZ header's e_minalloc value.
	**/
	word MzHeader::getMinExtraParagraphs() const
	{
		return m_idhHeader.e_minalloc;
	}

	/**
	* Returns the MZ header's e_maxalloc value.
	**/
	word MzHeader::getMaxExtraParagraphs() const
	{
		return m_idhHeader.e_maxalloc;
	}

	/**
	* Returns the MZ header's e_ss value.
	**/
	word MzHeader::getSsValue() const
	{
		return m_idhHeader.e_ss;
	}

	/**
	* Returns the MZ header's e_sp value.
	**/
	word MzHeader::getSpValue() const
	{
		return m_idhHeader.e_sp;
	}

	/**
	* Returns the MZ header's e_csum value.
	**/
	word MzHeader::getChecksum() const
	{
		return m_idhHeader.e_csum;
	}

	/**
	* Returns the MZ header's e_ip value.
	**/
	word MzHeader::getIpValue() const
	{
		return m_idhHeader.e_ip;
	}

	/**
	* Returns the MZ header's e_cs value.
	**/
	word MzHeader::getCsValue() const
	{
		return m_idhHeader.e_cs;
	}

	/**
	* Returns the MZ header's e_lfarlc value.
	**/
	word MzHeader::getAddrOfRelocationTable() const
	{
		return m_idhHeader.e_lfarlc;
	}

	/**
	* Returns the MZ header's e_ovno value.
	**/
	word MzHeader::getOverlayNumber() const
	{
		return m_idhHeader.e_ovno;
	}

	/**
	* Returns the MZ header's e_oemid value.
	**/
	word MzHeader::getOemIdentifier() const
	{
		return m_idhHeader.e_oemid;
	}

	/**
	* Returns the MZ header's e_oeminfo value.
	**/
	word MzHeader::getOemInformation() const
	{
		return m_idhHeader.e_oeminfo;
	}

	/**
	* Returns the MZ header's e_lfanew value.
	**/
	dword MzHeader::getAddressOfPeHeader() const
	{
		return m_idhHeader.e_lfanew;
	}

	/**
	* Returns the MZ header's e_res[uiNr] value. If the parameter uiNr is out of range
	* you will get undefined behaviour.
	* @param uiNr The index of the word in the e_res array (valid range: 0-3)
	**/
	word MzHeader::getReservedWords1(unsigned int uiNr) const
	{
		return m_idhHeader.e_res[uiNr];
	}

	/**
	* Returns the MZ header's e_res2[uiNr] value. If the parameter uiNr is out of range
	* you will get undefined behaviour.
	* @param uiNr The index of the word in the e_res array (valid range: 0-9)
	**/
	word MzHeader::getReservedWords2(unsigned int uiNr) const
	{
		return m_idhHeader.e_res2[uiNr];
	}

	/**
	* Sets the MZ header's e_magic value.
	* @param wValue The new value of e_magic.
	**/
	void MzHeader::setMagicNumber(word wValue)
	{
		m_idhHeader.e_magic = wValue;
	}

	/**
	* Sets the MZ header's e_cblp value.
	* @param wValue The new value of e_cblp.
	**/
	void MzHeader::setBytesOnLastPage(word wValue)
	{
		m_idhHeader.e_cblp = wValue;
	}

	/**
	* Sets the MZ header's e_cp value.
	* @param wValue The new value of e_cp.
	**/
	void MzHeader::setPagesInFile(word wValue)
	{
		m_idhHeader.e_cp = wValue;
	}

	/**
	* Sets the MZ header's e_crlc value.
	* @param wValue The new value of e_crlc.
	**/
	void MzHeader::setRelocations(word wValue)
	{
		m_idhHeader.e_crlc = wValue;
	}

	/**
	* Sets the MZ header's e_cparhdr value.
	* @param wValue The new value of e_cparhdr.
	**/
	void MzHeader::setSizeOfHeader(word wValue)
	{
		m_idhHeader.e_cparhdr = wValue;
	}

	/**
	* Sets the MZ header's e_minalloc value.
	* @param wValue The new value of e_minalloc.
	**/
	void MzHeader::setMinExtraParagraphs(word wValue)
	{
		m_idhHeader.e_minalloc = wValue;
	}

	/**
	* Sets the MZ header's e_maxalloc value.
	* @param wValue The new value of e_maxalloc.
	**/
	void MzHeader::setMaxExtraParagraphs(word wValue)
	{
		m_idhHeader.e_maxalloc = wValue;
	}

	/**
	* Sets the MZ header's e_ss value.
	* @param wValue The new value of e_ss.
	**/
	void MzHeader::setSsValue(word wValue)
	{
		m_idhHeader.e_ss = wValue;
	}

	/**
	* Sets the MZ header's e_sp value.
	* @param wValue The new value of e_sp.
	**/
	void MzHeader::setSpValue(word wValue)
	{
		m_idhHeader.e_sp = wValue;
	}

	/**
	* Sets the MZ header's e_csum value.
	* @param wValue The new value of e_csum.
	**/
	void MzHeader::setChecksum(word wValue)
	{
		m_idhHeader.e_csum = wValue;
	}

	/**
	* Sets the MZ header's e_ip value.
	* @param wValue The new value of e_ip.
	**/
	void MzHeader::setIpValue(word wValue)
	{
		m_idhHeader.e_ip = wValue;
	}

	/**
	* Sets the MZ header's e_cs value.
	* @param wValue The new value of e_cs.
	**/
	void MzHeader::setCsValue(word wValue)
	{
		m_idhHeader.e_cs = wValue;
	}

	/**
	* Sets the MZ header's e_lfarlc value.
	* @param wValue The new value of e_lfarlc.
	**/
	void MzHeader::setAddrOfRelocationTable(word wValue)
	{
		m_idhHeader.e_lfarlc = wValue;
	}

	/**
	* Sets the MZ header's e_ovno value.
	* @param wValue The new value of e_ovno.
	**/
	void MzHeader::setOverlayNumber(word wValue)
	{
		m_idhHeader.e_ovno = wValue;
	}

	/**
	* Sets the MZ header's e_oemid value.
	* @param wValue The new value of e_oemid.
	**/
	void MzHeader::setOemIdentifier(word wValue)
	{
		m_idhHeader.e_oemid = wValue;
	}

	/**
	* Sets the MZ header's e_oeminfo value.
	* @param wValue The new value of e_oeminfo.
	**/
	void MzHeader::setOemInformation(word wValue)
	{
		m_idhHeader.e_oeminfo = wValue;
	}

	/**
	* Sets the MZ header's e_lfanew value.
	* @param lValue The new value of e_lfanew.
	**/
	void MzHeader::setAddressOfPeHeader(dword lValue)
	{
		m_idhHeader.e_lfanew = lValue;
	}

	/**
	* Sets the MZ header's e_res[uiNr] value. If the parameter uiNr is out of range
	* you will get undefined behaviour.
	* @param uiNr The index of the word in the e_res array (valid range: 0-3)
	* @param wValue The new value of e_res[nr].
	**/
	void MzHeader::setReservedWords1(unsigned int uiNr, word wValue)
	{
		m_idhHeader.e_res[uiNr] = wValue;
	}

	/**
	* Sets the MZ header's e_res2[uiNr] value. If the parameter uiNr is out of range
	* you will get undefined behaviour.
	* @param uiNr The index of the word in the e_res2 array (valid range: 0-9)
	* @param wValue The new value of e_res[nr].
	**/
	void MzHeader::setReservedWords2(unsigned int uiNr, word wValue)
	{
		m_idhHeader.e_res2[uiNr] = wValue;
	}

}
