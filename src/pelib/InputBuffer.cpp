/*
* InputBuffer.cpp - Part of the PeLib library.
*
* Copyright (c) 2004 - 2005 Sebastian Porst (webmaster@the-interweb.com)
* All rights reserved.
*
* This software is licensed under the zlib/libpng License.
* For more details see http://www.opensource.org/licenses/zlib-license.php
* or the license information file (license.htm) in the root directory
* of PeLib.
*/

#include "retdec/pelib/InputBuffer.h"

namespace PeLib
{
	InputBuffer::InputBuffer(std::vector<unsigned char>& vBuffer) : m_vBuffer(vBuffer), ulIndex(0)
	{
	}

	const unsigned char* InputBuffer::data() const
	{
		return m_vBuffer.data();
	}

	unsigned long InputBuffer::size()
	{
		return static_cast<unsigned long>(m_vBuffer.size());
	}

	void InputBuffer::read(char* lpBuffer, unsigned long ulSize)
	{
		if (ulIndex >= m_vBuffer.size())
			return;

		ulSize = (unsigned long)(ulIndex + ulSize > m_vBuffer.size() ? m_vBuffer.size() - ulIndex : ulSize);

		std::copy(m_vBuffer.data() + ulIndex, m_vBuffer.data() + ulIndex + ulSize, lpBuffer);
		ulIndex += ulSize;
	}

	void InputBuffer::reset()
	{
		m_vBuffer.clear();
	}

	void InputBuffer::set(unsigned long ulIndex2)
	{
		this->ulIndex = ulIndex2;
	}

	void InputBuffer::move(unsigned long shift)
	{
		ulIndex += shift;
	}

	unsigned long InputBuffer::get()
	{
		return ulIndex;
	}

	void InputBuffer::setBuffer(std::vector<unsigned char>& vBuffer)
	{
		m_vBuffer = vBuffer;
		ulIndex = 0;
	}
}
