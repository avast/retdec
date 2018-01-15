// //////////////////////////////////////////////////////////
// crc32.h
// Copyright (c) 2014,2015 Stephan Brumme. All rights reserved.
// see http://create.stephan-brumme.com/disclaimer.html
//

// !!!
// The source code was slightly modified in order to fix compilation warnings
// and conform to the coding standards of the RetDec project.
// !!!

#ifndef RETDEC_CRYPTO_CRC32_H
#define RETDEC_CRYPTO_CRC32_H

//#include "hash.h"
#include <string>

// define fixed size integer types
#ifdef _MSC_VER
// Windows
using uint8_t = unsigned __int8;
using uint32_t = unsigned __int32;
#else
// GCC
#include <cstdint>
#endif

/// compute CRC32 hash, based on Intel's Slicing-by-8 algorithm
/** Usage:
	CRC32 crc32;
	std::string myHash  = crc32("Hello World");     // std::string
	std::string myHash2 = crc32("How are you", 11); // arbitrary data, 11 bytes

	// or in a streaming fashion:

	CRC32 crc32;
	while (more data available)
	  crc32.add(pointer to fresh data, number of new bytes);
	std::string myHash3 = crc32.getHash();

	Note:
	You can find code for the faster Slicing-by-16 algorithm on my website, too:
	http://create.stephan-brumme.com/crc32/
	Its unrolled version is about twice as fast but its look-up table doubled in size as well.
*/
class CRC32 //: public Hash
{
public:
	/// hash is 4 bytes long
	enum { HashBytes = 4 };

	/// same as reset()
	CRC32();

	/// compute CRC32 of a memory block
	std::string operator()(const void* data, size_t numBytes);
	/// compute CRC32 of a string, excluding final zero
	std::string operator()(const std::string& text);

	/// add arbitrary number of bytes
	void add(const void* data, size_t numBytes);

	/// return latest hash as 8 hex characters
	std::string getHash();
	/// return latest hash as bytes
	void        getHash(unsigned char buffer[CRC32::HashBytes]);

	/// restart
	void reset();

private:
	/// hash
	uint32_t m_hash;
};

#endif
