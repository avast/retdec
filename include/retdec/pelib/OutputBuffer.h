/*
* OutputBuffer.h - Part of the PeLib library.
*
* Copyright (c) 2004 - 2005 Sebastian Porst (webmaster@the-interweb.com)
* All rights reserved.
*
* This software is licensed under the zlib/libpng License.
* For more details see http://www.opensource.org/licenses/zlib-license.php
* or the license information file (license.htm) in the root directory
* of PeLib.
*/

#ifndef OUTPUTBUFFER_H
#define OUTPUTBUFFER_H

#include <vector>
#include <iterator>

namespace PeLib
{
	class OutputBuffer
	{
		private:
		  std::vector<unsigned char>& m_vBuffer;

		public:
		  OutputBuffer(std::vector<unsigned char>& vBuffer);
		  const unsigned char* data() const;
		  unsigned long size();

		  template<typename T>
		  OutputBuffer& operator<<(const T& value)
		  {
			const unsigned char* p = reinterpret_cast<const unsigned char*>(&value);
			std::copy(p, p + sizeof(value), std::back_inserter(m_vBuffer));
			return *this;
		  }
		  void add(const char* lpBuffer, unsigned long ulSize);
		  void reset();
		  void resize(unsigned int uiSize);
		  void set(unsigned int uiPosition);

		  template<typename T>
		  void update(unsigned long ulIndex, const T& value)
		  {
			*reinterpret_cast<T*>(m_vBuffer.data() + ulIndex) = value;
		  }

		  template<typename T>
		  void insert(unsigned long ulIndex, const T& value)
		  {
			if (ulIndex + sizeof(T) >= size())
				resize(ulIndex + sizeof(T));

			update(ulIndex, value);
		  }
	};
}

#endif
