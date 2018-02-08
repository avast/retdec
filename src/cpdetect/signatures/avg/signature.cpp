/**
 * @file src/cpdetect/signatures/avg/signature.cpp
 * @brief Definiton of compiler or packer signature.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/cpdetect/signatures/avg/signature.h"
#include "retdec/cpdetect/signatures/avg/signature_checker.h"

namespace retdec {
namespace cpdetect {

/**
 * Constructor
 */
Signature::Signature() : startOffset(0), endOffset(0)
{

}

/**
 * Constructor
 * @param sName Name of compiler or packer
 * @param sVersion Version of used compiler or packer
 * @param sPattern Signature pattern
 * @param sAdditional Additional information about used compiler or packer
 * @param sStart Start offset of pattern
 * @param sEnd End offset of pattern
 */
Signature::Signature(
		std::string sName, std::string sVersion, std::string sPattern, std::string sAdditional,
		unsigned sStart, unsigned sEnd)
	: name(sName), version(sVersion), pattern(sPattern), additional(sAdditional),
		startOffset(sStart), endOffset(sEnd)
{

}

/**
 * Destructor
 */
Signature::~Signature()
{

}

/**
 * Check if signature have pattern in valid format
 * @return @c true if signature have pattern in valid format, @c false otherwise
 */
bool Signature::haveValidPattern() const
{
	return isValidSignaturePattern(pattern);
}

} // namespace cpdetect
} // namespace retdec
