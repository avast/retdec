/**
 * @file src/cpdetect/compiler_detector/search/search.cpp
 * @brief Class for search in file.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <map>

#include "retdec/utils/container.h"
#include "retdec/utils/conversion.h"
#include "retdec/utils/equality.h"
#include "retdec/utils/string.h"
#include "retdec/cpdetect/compiler_detector/search/search.h"
#include "retdec/cpdetect/signatures/avg/signature_checker.h"
#include "retdec/fileformat/utils/conversions.h"
#include "retdec/fileformat/utils/file_io.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace retdec {
namespace cpdetect {

namespace
{

const std::map<Architecture, std::vector<Search::RelativeJump>> jumpMap =
{
	{Architecture::X86, {Search::RelativeJump("EB", 1), Search::RelativeJump("E9", 4)}},
	{Architecture::X86_64, {Search::RelativeJump("EB", 1), Search::RelativeJump("E9", 4)}}
};

} // anonymous namespace

/**
 * Constructor
 * @param fileParser Parser of input file
 */
Search::Search(retdec::fileformat::FileFormat &fileParser) : parser(fileParser), averageSlashLen(0)
{
	const auto &bytes = parser.getLoadedBytes();
	bytesToHexString(bytes, nibbles);
	bytesToString(bytes, plain);
	fileLoaded = !bytes.empty();
	fileSupported = parser.hexToLittle(nibbles) && parser.getNumberOfNibblesInByte();
	jumps = mapGetValueOrDefault(jumpMap, parser.getTargetArchitecture(), std::vector<RelativeJump>());

	for(std::size_t i = 0, e = jumps.size(); i < e; ++i)
	{
		const auto len = jumps[i].getSlashNibbleSize();
		averageSlashLen += len;
		if(!len)
		{
			jumps.erase(jumps.begin() + i);
			--i;
			--e;
		}
	}

	if(averageSlashLen)
	{
		averageSlashLen /= jumps.size();
	}
}

/**
 * Destructor
 */
Search::~Search()
{

}

/**
 * Constructor of RelativeJump
 */
Search::RelativeJump::RelativeJump(std::string sSlash, std::size_t sBytesAfter) : slash(sSlash), bytesAfter(sBytesAfter)
{

}

/**
 * Destructor of RelativeJump
 */
Search::RelativeJump::~RelativeJump()
{

}

/**
 * Get slash pattern
 * @return Slash pattern
 */
std::string Search::RelativeJump::getSlash() const
{
	return slash;
}

/**
 * Get size of slash in nibbles
 */
std::size_t Search::RelativeJump::getSlashNibbleSize() const
{
	return slash.size();
}

/**
 * Get number of bytes after slash pattern
 * @return Number of bytes after slash pattern
 */
std::size_t Search::RelativeJump::getBytesAfter() const
{
	return bytesAfter;
}

/**
 * Check is some slashes are defined for target architecture of input file
 * @return @c true if at least one slash pattern is defined for target architecture
 *    of input file, @c false otherwise
 */
bool Search::haveSlashes() const
{
	return !jumps.empty();
}

/**
 * Count number of nibbles from number of bytes
 * @param nBytes Number of bytes
 * @return Number of nibbles
 */
std::size_t Search::nibblesFromBytes(std::size_t nBytes) const
{
	return parser.nibblesFromBytes(nBytes);
}

/**
 * Count number of bytes from number of nibbles
 * @param nNibbles Number of nibbles
 * @return Number of bytes
 */
std::size_t Search::bytesFromNibbles(std::size_t nNibbles) const
{
	return parser.bytesFromNibbles(nNibbles);
}

/**
 * Check if input file was successfully loaded
 * @return @c true if file was successfully loaded, @c false otherwise
 */
bool Search::isFileLoaded() const
{
	return fileLoaded;
}

/**
 * Check if input file is supported for search
 * @return @c true if input file is supported for search, @c false otherwise
 */
bool Search::isFileSupported() const
{
	return fileSupported;
}

/**
 * Get content of file in hexadecimal string representation
 * @return Content of file in hexadecimal string representation
 */
const std::string& Search::getNibbles() const
{
	return nibbles;
}

/**
 * Get content of file as plain string
 * @return Content of file as plain string
 */
const std::string& Search::getPlainString() const
{
	return plain;
}

/**
 * Check if relative jump is present on offset @a fileOffset
 * @param fileOffset Byte offset in file
 * @param shift Relative shift in nibbles from @a fileOffset
 * @param moveSize Into this parameter is stored number of nibbles of which will jump or zero
 *    if @c nullptr is returned
 * @return Pointer to the description of detected jump of @c nullptr if jump is not detected
 */
const Search::RelativeJump* Search::getRelativeJump(std::size_t fileOffset, std::size_t shift, std::int64_t &moveSize) const
{
	const auto nibbleOffset = nibblesFromBytes(fileOffset) + shift;
	moveSize = 0;

	for(const auto &jump : jumps)
	{
		const auto nibblesAfter = nibblesFromBytes(jump.getBytesAfter());
		if(!hasSubstringOnPosition(nibbles, jump.getSlash(), nibbleOffset) ||
			(nibbleOffset + jump.getSlashNibbleSize() + nibblesAfter - 1 >= nibbles.length()))
		{
			continue;
		}

		std::uint64_t jumpedBytes = 0;
		if(!parser.getXByteOffset(fileOffset + bytesFromNibbles(jump.getSlashNibbleSize()), jump.getBytesAfter(), jumpedBytes, Endianness::LITTLE))
		{
			continue;
		}

		moveSize = static_cast<std::int64_t>(jumpedBytes);
		switch(jump.getBytesAfter())
		{
			case 1:
				moveSize = static_cast<std::int8_t>(moveSize);
				break;
			case 2:
				moveSize = static_cast<std::int16_t>(moveSize);
				break;
			case 4:
				moveSize = static_cast<std::int32_t>(moveSize);
				break;
			case 8:
				moveSize = static_cast<std::int64_t>(moveSize);
				break;
			default:
				assert(false && "Unexpected value of a switch expression");
		}

		moveSize = nibblesFromBytes(moveSize);
		return &jump;
	}

	return nullptr;
}

/**
 * Count number of significant nibbles in signature pattern
 * @param signPattern Signature pattern
 * @return Number of significant nibbles in signature pattern
 */
unsigned long long Search::countImpNibbles(const std::string &signPattern) const
{
	unsigned long long count = 0;

	for(const auto &c : signPattern)
	{
		if(c == '/')
		{
			count += averageSlashLen;
		}
		else if(c != '-' && c != '?' && c != ';')
		{
			++count;
		}
	}

	return count;
}

/**
 * Method tells if there is the pattern in selected area of file. Unable for slashed signatures
 * @param signPattern Signature pattern
 * @param startOffset Start offset in file (in bytes)
 * @param stopOffset Stop offset in file (in bytes)
 * @return If pattern is present in area return number of patterns significant nibbles, else return 0
 */
unsigned long long Search::findUnslashedSignature(const std::string &signPattern, std::size_t startOffset, std::size_t stopOffset) const
{
	if(startOffset > stopOffset)
	{
		return 0;
	}

	const auto startIterator = nibbles.begin() + nibblesFromBytes(startOffset);
	const auto stopIndex = nibblesFromBytes(stopOffset) + 1;
	const auto stopIterator = stopIndex < nibbles.size() ? nibbles.begin() + stopIndex : nibbles.end();
	const auto it = std::search(startIterator, stopIterator, signPattern.begin(), signPattern.end(),
		[] (const char fileNibble, const char signatureNibble)
		{
			return fileNibble == signatureNibble || signatureNibble == '-' || signatureNibble == '?' || signatureNibble == ';';
		}
	);

	return (it != stopIterator) ? countImpNibbles(signPattern) : 0;
}

/**
 * Search if there is a slash(es) containing pattern in selected area
 * @param signPattern Signature pattern
 * @param startOffset Start offset in file (in bytes)
 * @param stopOffset Stop offset in file (in bytes)
 * @return If pattern is not present in area return 0, else return number of patterns significant nibbles
 */
unsigned long long Search::findSlashedSignature(const std::string &signPattern, std::size_t startOffset, std::size_t stopOffset) const
{
	if(startOffset > stopOffset)
	{
		return 0;
	}

	const auto areaSize = nibblesFromBytes(stopOffset - startOffset + 1);
	const auto signSize = signPattern.length() - std::count(signPattern.begin(), signPattern.end(), ';');
	if(areaSize < signSize)
	{
		return false;
	}
	const auto iters = (startOffset == stopOffset) ? 1 : areaSize - signSize + 1;

	for(std::size_t i = 0; i < iters; ++i)
	{
		const auto result = exactComparison(signPattern, startOffset, i);
		if(result)
		{
			return result;
		}
	}

	return 0;
}

/**
 * Try find signature @a signPattern at specified offset
 * @param signPattern Signature pattern
 * @param fileOffset Offset in file
 * @param shift Relative shift in nibbles from @a fileOffset
 * @return Number of significant nibbles of signature or 0 if content of file and signature are different
 */
unsigned long long Search::exactComparison(const std::string &signPattern, std::size_t fileOffset, std::size_t shift) const
{
	for(std::size_t sigIndex = 0, fileIndex = nibblesFromBytes(fileOffset) + shift, fileLen = nibbles.length();
		fileIndex < fileLen; ++sigIndex, ++fileIndex)
	{
		if(sigIndex == signPattern.length() || signPattern[sigIndex] == ';')
		{
			return countImpNibbles(signPattern);
		}
		else if(signPattern[sigIndex] == '/')
		{
			std::int64_t moveSize = 0;
			const auto actShift = (parser.getNumberOfNibblesInByte() ? fileIndex % parser.getNumberOfNibblesInByte() : 0);
			const auto *jump = getRelativeJump(bytesFromNibbles(fileIndex), actShift, moveSize);
			if(!jump)
			{
				if(!haveSlashes())
				{
					--fileIndex;
					continue;
				}

				return 0;
			}

			// move after one nibble is in header of cycle
			fileIndex += jump->getSlashNibbleSize() + nibblesFromBytes(jump->getBytesAfter()) + moveSize - 1;
		}
		else if(signPattern[sigIndex] != nibbles[fileIndex] && signPattern[sigIndex] != '-' && signPattern[sigIndex] != '?')
		{
			return 0;
		}
	}

	return 0;
}

/**
 * Count similarity as count of agree nibbles and count of valuable nibbles in signature
 * @param signPattern Signature pattern
 * @param sim Structure for save similarity
 * @param fileOffset Offset in file
 * @param shift Relative shift in nibbles from @a fileOffset
 * @return @c true if function went OK, @c false otherwise
 *
 * If function return @c false, @a sim is left unchanged
 */
bool Search::countSimilarity(const std::string &signPattern, Similarity &sim, std::size_t fileOffset, std::size_t shift) const
{
	Similarity result;

	for(std::size_t sigIndex = 0, fileIndex = nibblesFromBytes(fileOffset) + shift, fileLen = nibbles.length(); fileIndex < fileLen; ++sigIndex, ++fileIndex)
	{
		if(sigIndex == signPattern.length() || signPattern[sigIndex] == ';')
		{
			sim.same = result.same;
			sim.total = result.total;
			sim.ratio = static_cast<double>(result.same) / result.total;
			return countImpNibbles(signPattern);
		}
		else if(signPattern[sigIndex] == '-' || signPattern[sigIndex] == '?')
		{
			continue;
		}
		else if(signPattern[sigIndex] == '/')
		{
			std::int64_t moveSize = 0;
			const auto actShift = (parser.getNumberOfNibblesInByte() ? fileIndex % parser.getNumberOfNibblesInByte() : 0);
			const auto *jump = getRelativeJump(bytesFromNibbles(fileIndex), actShift, moveSize);
			if(!jump)
			{
				if(!haveSlashes())
				{
					--fileIndex;
					continue;
				}

				result.total += averageSlashLen;
			}
			else
			{
				result.total += jump->getSlashNibbleSize();
				result.same += jump->getSlashNibbleSize();
				fileIndex += jump->getSlashNibbleSize() + nibblesFromBytes(jump->getBytesAfter()) + moveSize - 1;
			}
			continue;
		}
		else if(signPattern[sigIndex] == nibbles[fileIndex])
		{
			++result.same;
		}

		++result.total;
	}

	return false;
}

/**
 * Count the most similar similarity in area
 * @param signPattern Signature pattern
 * @param sim Structure for save similarity
 * @param startOffset Start offset in file (in bytes)
 * @param stopOffset Stop offset in file (in bytes)
 * @return @c true if function went OK, @c false otherwise
 *
 * If function return @c false, @a sim is left unchanged
 */
bool Search::areaSimilarity(const std::string &signPattern, Similarity &sim, std::size_t startOffset, std::size_t stopOffset) const
{
	if(startOffset > stopOffset)
	{
		return false;
	}

	const auto areaSize = nibblesFromBytes(stopOffset - startOffset + 1);
	const auto signSize = signPattern.length() - std::count(signPattern.begin(), signPattern.end(), ';');
	if(areaSize < signSize)
	{
		return false;
	}
	const auto iters = (startOffset == stopOffset) ? 1 : areaSize - signSize + 1;
	auto result = false;
	Similarity act, max;

	for(std::size_t i = 0; i < iters; ++i)
	{
		if(countSimilarity(signPattern, act, startOffset, i) &&
			(act.ratio > max.ratio || (areEqual(act.ratio, max.ratio) && act.total > max.total)))
		{
			max.same = act.same;
			max.total = act.total;
			max.ratio = act.ratio;
			result = true;
		}
	}

	if(result)
	{
		sim.same = max.same;
		sim.total = max.total;
		sim.ratio = max.ratio;
	}

	return result;
}

/**
 * Check if file contains specified substring
 * @param str Coveted substring
 * @return @c true if file contains @a str, @c false otherwise
 */
bool Search::hasString(const std::string &str) const
{
	return contains(plain, str);
}

/**
 * Check if file has substring @a str on specified offset
 * @param str Coveted substring
 * @param fileOffset Offset in file
 * @return @c true if file has @a str on offset @a fileOffset, @c false otherwise
 */
bool Search::hasString(const std::string &str, std::size_t fileOffset) const
{
	return hasSubstringOnPosition(plain, str, fileOffset);
}

/**
 * Check if file contains string in selected area of file
 * @param str Coveted string
 * @param startOffset Start offset in file (in bytes)
 * @param stopOffset Stop offset in file (in bytes)
 * @return @c true if string is present in selected area of file, @c false otherwise
 */
bool Search::hasString(const std::string &str, std::size_t startOffset, std::size_t stopOffset) const
{
	return hasSubstringInArea(plain, str, startOffset, stopOffset);
}

/**
 * Check if file contains string in selected section
 * @param str Coveted string
 * @param section Selected section
 * @return @c true if string is present in selected section, @c false otherwise
 */
bool Search::hasStringInSection(const std::string &str, const retdec::fileformat::Section *section) const
{
	return section && hasString(str, section->getOffset(), section->getOffset() + section->getLoadedSize() - 1);
}

/**
 * Check if file contains string in selected section
 * @param str Coveted string
 * @param sectionIndex Index of selected section (indexed from 0)
 * @return @c true if string is present in selected section, @c false otherwise
 */
bool Search::hasStringInSection(const std::string &str, std::size_t sectionIndex) const
{
	return hasStringInSection(str, parser.getSection(sectionIndex));
}

/**
 * Check if file contains string in selected section
 * @param str Coveted string
 * @param sectionName Name of selected section
 * @return @c true if string is present in selected section, @c false otherwise
 */
bool Search::hasStringInSection(const std::string &str, const std::string &sectionName) const
{
	return hasStringInSection(str, parser.getSection(sectionName));
}

/**
 * Create signature from specified offset
 * @param pattern Into this parameter is stored resulted signature
 * @param fileOffset Start offset in file (in bytes)
 * @param size Desired length of signature (in bytes, slashes are also considered
 *    as one byte during creation of signature)
 * @return @c true if signature was successfully created, @c false otherwise
 */
bool Search::createSignature(std::string &pattern, std::size_t fileOffset, std::size_t size) const
{
	pattern.clear();

	for(std::size_t i = 0, fileIndex = nibblesFromBytes(fileOffset), fileLen = nibbles.length(), nibbleSize = nibblesFromBytes(size);
		fileIndex < fileLen && i < nibbleSize; ++i, ++fileIndex)
	{
		std::int64_t moveSize = 0;
		const auto actShift = (parser.getNumberOfNibblesInByte() ? fileIndex % parser.getNumberOfNibblesInByte() : 0);
		const auto *jump = getRelativeJump(bytesFromNibbles(fileIndex), actShift, moveSize);
		if(jump)
		{
			pattern += '/';
			fileIndex += jump->getSlashNibbleSize() + nibblesFromBytes(jump->getBytesAfter()) + moveSize - 1;
		}
		else
		{
			pattern += nibbles[fileIndex];
		}
	}

	pattern += ';';
	return isValidSignaturePattern(pattern);
}

} // namespace cpdetect
} // namespace retdec
