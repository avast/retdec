/*
* InputBuffer.h - Part of the PeLib library.
*
* Copyright (c) 2004 - 2005 Sebastian Porst (webmaster@the-interweb.com)
* All rights reserved.
*
* This software is licensed under the zlib/libpng License.
* For more details see http://www.opensource.org/licenses/zlib-license.php
* or the license information file (license.htm) in the root directory
* of PeLib.
*/

#ifndef RETDEC_PELIB_INPUTBUFFER_H
#define RETDEC_PELIB_INPUTBUFFER_H

#include <vector>
#include <iterator>
#include <cassert>

namespace PeLib
{
	class InputBuffer
	{
		private:
		  std::vector<unsigned char>& m_vBuffer;
		  unsigned long ulIndex;

		public:
		  InputBuffer(std::vector<unsigned char>& vBuffer);

		  const unsigned char* data() const;
		  unsigned long size();

		  template<typename T>
		  InputBuffer& operator>>(T& value)
		  {
//jk: temporarily disabled because of fails on 64bit systems
//			assert(ulIndex + sizeof(value) <= m_vBuffer.size());

			std::vector<char> data(sizeof(T), 0);
			std::size_t size = ulIndex + sizeof(T) > m_vBuffer.size() ? m_vBuffer.size() - ulIndex : sizeof(T);
			read(data.data(), (unsigned long)size);
			value = *reinterpret_cast<T*>(data.data());
			return *this;
		  }

		  void read(char* lpBuffer, unsigned long ulSize);
		  void reset();
		  void set(unsigned long ulIndex2);
		  void move(unsigned long shift);
		  unsigned long get();
		  void setBuffer(std::vector<unsigned char>& vBuffer);
//		  void updateData(unsigned long ulIndex,
	};
}

#endif
