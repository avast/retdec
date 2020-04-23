/**
 * @file include/retdec/cpdetect/signature.h
 * @brief Definiton of compiler or packer signature.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CPDETECT_SIGNATURE_H
#define RETDEC_CPDETECT_SIGNATURE_H

#include <string>

namespace retdec {
namespace cpdetect {

/*

Signature for description of used compiler or packer

NEW AVG SIGNATURE FORMAT USED IN THIS PROGRAM
0 (A)
0 (B)
"FCB8------??B9--------81F9--------750681C1270000003001C1C0034181F9--??----75E4;" (C)

Parts:
	A - start distance of search (decimal) from EP
	B - end distance of search (decimal) from EP
	C - pattern

Note:
	A and B are 0, it means that pattern can be only on the first position.
	If A and B are UINT_MAX, it means that pattern placement is unspecified.

	Patterns are in little endian, semicolon at end of pattern is optional.

PATTERN FORMAT:
	FF -> one byte value
	-- -> one variable byte
	8- -> variable nibble

	? -> equal to -

	/ -> unconditional jump
			- the first byte on slash position must be EB or E9 (on x86)
			- the first byte (after EB) or the first 4 bytes (after E9) tells
				us how many bytes we must skip (this number is signed)
			- next part of the pattern we compare after skipped bytes
			- examples of agreement:
				pattern: "/EB--536861726577617265202D20;"
				file: EB03------EB--536861726577617265202D20
						xx ---> * skip here
				pattern: "/EB--536861726577617265202D20;"
				file: EB02----EB--536861726577617265202D20
						xx -> * skip here
				pattern: "/536861726577617265202D20;"
				file: E903000000------536861726577617265202D20
						xx ---------> * skip here
*/
class Signature
{
	public:
		std::string name;       ///< name of used tool
		std::string version;    ///< version of used tool
		std::string pattern;    ///< signature pattern
		std::string additional; ///< additional information about tool
		unsigned startOffset = 0;   ///< start offset of pattern
		unsigned endOffset = 0;     ///< end offset of pattern

		Signature(
				std::string sName,
				std::string sVersion,
				std::string sPattern,
				std::string sAdditional = "",
				unsigned sStart = 0,
				unsigned sEnd = 0
		);

		static bool isValidSignaturePattern(const std::string& pattern);
};

} // namespace cpdetect
} // namespace retdec

#endif
