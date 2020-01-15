/*
* PeHeader.cpp - Part of the PeLib library.
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
#include "pelib/PeHeader.h"

namespace PeLib
{
	template<>
	void PeHeaderT<32>::readBaseOfData(InputBuffer& ibBuffer, PELIB_IMAGE_NT_HEADERS<32>& header) const
	{
		ibBuffer >> header.OptionalHeader.BaseOfData;
	}

	template<>
	void PeHeaderT<64>::readBaseOfData(InputBuffer&, PELIB_IMAGE_NT_HEADERS<64>&) const
	{
	}

	template<>
	void PeHeaderT<32>::rebuildBaseOfData(OutputBuffer& obBuffer) const
	{
		obBuffer << m_inthHeader.OptionalHeader.BaseOfData;
	}

	template<>
	void PeHeaderT<64>::rebuildBaseOfData(OutputBuffer&) const
	{
	}

	template<>
	bool PeHeaderT<32>::isValid() const
	{
		return true;
	}

	template<>
	bool PeHeaderT<64>::isValid() const
	{
		return true;
	}

	template<>
	bool PeHeaderT<32>::isValid(unsigned int pehf) const
	{
		(void) pehf; /* avoid warning about unused parameter */
	/*
		if (pehf == NtSignature)
		{
			return m_inthHeader.Signature == IMAGE_NT_SIGNATURE;
		}
		else if (pehf == NumberOfSections)
		{
			return getNumberOfSections() == calcNumberOfSections();
		}  */
		return false;
	}

	template<>
	bool PeHeaderT<64>::isValid(unsigned int pehf) const
	{
		(void) pehf; /* avoid warning about unused parameter */
		return false;
	}

	/**
	* @return The BaseOfData value from the PE header.
	**/
	dword PeHeader32::getBaseOfData() const
	{
		return m_inthHeader.OptionalHeader.BaseOfData;
	}

	/**
	* Changes the file's BaseOfData.
	* @param dwValue New value.
	**/
	void PeHeader32::setBaseOfData(dword dwValue)
	{
		m_inthHeader.OptionalHeader.BaseOfData = dwValue;
	}

}
