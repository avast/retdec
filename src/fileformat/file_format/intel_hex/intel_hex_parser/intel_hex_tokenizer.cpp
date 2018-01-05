/**
 * @file src/fileformat/file_format/intel_hex/intel_hex_parser/intel_hex_tokenizer.cpp
 * @brief Definition of IntelHexToken and IntelHexTokenizer classes.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cassert>

#include "retdec/utils/conversion.h"
#include "retdec/fileformat/file_format/intel_hex/intel_hex_parser/intel_hex_parser.h"
#include "retdec/fileformat/file_format/intel_hex/intel_hex_parser/intel_hex_tokenizer.h"

using namespace retdec::utils;

namespace retdec {
namespace fileformat {

/**
 * Constructor
 */
IntelHexToken::IntelHexToken()
{

}

/**
 * Destructor
 */
IntelHexToken::~IntelHexToken()
{

}

/**
 * Adds chars of string by two (one data byte) for checksum
 * @param str Input string
 * @return Sum of chars by two in string
 *
 * @warning Function only works with even size of string (this is granted in Intel HEX)
 */
int IntelHexToken::addStringByTwo(const std::string &str)
{
	assert(str.size() % 2 == 0);

	int result = 0;

	for(std::string::size_type i = 0; i < str.size(); i += 2)
	{
		std::string tmp_str;
		tmp_str.push_back(str[i]);
		tmp_str.push_back(str[i+1]);
		result = result + IntelHexParser::strToInt(tmp_str);
	}

	return result;
}

/**
 * Verifies checksum
 */
void IntelHexToken::controlChecksum()
{
	int csum;
	csum = byteCount;
	csum += recordType;
	csum += addStringByTwo(address);
	csum += addStringByTwo(data);
	csum = 0 - csum;     // Two's complement
	csum = csum & 0x0FF; // Truncate upper bits

	checksumValid = (csum == static_cast<int>(IntelHexParser::strToInt(checksum)));
}

/**
 * Constructor
 */
IntelHexTokenizer::IntelHexTokenizer()
{

}

/**
 * Destructor
 */
IntelHexTokenizer::~IntelHexTokenizer()
{

}

/**
 * Reads @a n characters from source
 * @param n Number of characters to read
 * @return String that was read
 */
std::string IntelHexTokenizer::readN(unsigned n)
{
	std::string result;

	for(unsigned i = 0; i < n; ++i)
	{
		result += source->get();
	}

	return result;
}

/**
 * Creates and formats error token
 * @param errorMessage Error message to send
 * @return Formatted error token
 */
IntelHexToken IntelHexTokenizer::makeErrorToken(const std::string &errorMessage)
{
	IntelHexToken token;
	token.recordType = IntelHexToken::REC_TYPE::RT_ERROR;
	token.errorDesc = errorMessage;
	return token;
}

/**
 * Get next token
 * @return Next token
 */
IntelHexToken IntelHexTokenizer::getToken()
{
	IntelHexToken token;
	// Starting colon
	char c = source->get();
	if(c != ':')
	{
		return makeErrorToken("Starting semicolon missing.");
	}

	// Byte count
	std::string tmp_str = readN(2);
	if(!strToNum(tmp_str, token.byteCount, std::hex))
	{
		return makeErrorToken("Invalid byte count sequence.");
	}

	// Address
	token.address = readN(4);
	if(!IntelHexParser::isHexadec(token.address))
	{
		return makeErrorToken("Invalid address sequence.");
	}

	// Record type
	tmp_str = readN(2);
	// Max. type number is 5
	if(!strToNum(tmp_str, token.recordType, std::hex) || token.recordType > 5)
	{
		return makeErrorToken("Invalid record type sequence.");
	}

	// Data
	token.data = readN(2 * token.byteCount);
	if(!IntelHexParser::isHexadec(token.data))
	{
		return makeErrorToken("Invalid data sequence.");
	}

	// Checksum
	token.checksum = readN(2);
	token.controlChecksum();
	if(!token.checksumValid)
	{
		return makeErrorToken("Invalid checksum.");
	}

	// Newline delimiters
	while(token.recordType != IntelHexToken::REC_TYPE::RT_EOFILE)
	{
		char c = source->get();
		if(c == '\r' || c == '\n')
		{
			continue;
		}
		else if(c == ':')
		{
			// New record
			source->unget();
			break;
		}
		else
		{
			// Error
			return makeErrorToken("Invalid newline sequence.");
		}
	}

	return token;
}

/**
 * Opens the file to analyze
 * @param pathToFile Path to input file
 * @return @c true on success, @c false otherwise
 */
bool IntelHexTokenizer::openFile(const std::string &pathToFile)
{
	fstr.open(pathToFile);
	return fstr.is_open() ? setInputStream(fstr) : false;
}

/**
 * Sets input stream to find tokens in
 * @param inputStream Reference to std::istream
 * @return True on success, false otherwise
 */
bool IntelHexTokenizer::setInputStream(std::istream &inputStream)
{
	if(!inputStream)
	{
		return false;
	}

	source = &inputStream;
	return true;
}

} // namespace fileformat
} // namespace retdec
