/*
* OutputBuffer.cpp - Part of the PeLib library.
*
* Copyright (c) 2004 - 2005 Sebastian Porst (webmaster@the-interweb.com)
* All rights reserved.
*
* This software is licensed under the zlib/libpng License.
* For more details see http://www.opensource.org/licenses/zlib-license.php
* or the license information file (license.htm) in the root directory
* of PeLib.
*/

#include "pelib/OutputBuffer.h"

namespace PeLib
{
	OutputBuffer::OutputBuffer(std::vector<unsigned char>& vBuffer) : m_vBuffer(vBuffer)
	{
		m_vBuffer.clear();
	}

	const unsigned char* OutputBuffer::data() const
	{
		return m_vBuffer.data();
	}

	unsigned long OutputBuffer::size()
	{
		return static_cast<unsigned long>(m_vBuffer.size());
	}

	void OutputBuffer::add(const char* lpBuffer, unsigned long ulSize)
	{
		std::copy(lpBuffer, lpBuffer + ulSize, std::back_inserter(m_vBuffer));
	}

	void OutputBuffer::reset()
	{
		m_vBuffer.clear();
	}

	void OutputBuffer::resize(unsigned int uiSize)
	{
		m_vBuffer.resize(uiSize);
	}
}
