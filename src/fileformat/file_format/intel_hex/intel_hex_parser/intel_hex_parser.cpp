/**
 * @file src/fileformat/file_format/intel_hex/intel_hex_parser/intel_hex_parser.cpp
 * @brief Definition of IntelHexSection and IntelHexParser classes.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <cassert>

#include "retdec/utils/conversion.h"
#include "retdec/fileformat/file_format/intel_hex/intel_hex_parser/intel_hex_parser.h"

using namespace retdec::utils;

namespace retdec {
namespace fileformat {

/**
 * Constructor
 */
IntelHexSection::IntelHexSection()
{

}

/**
 * Destructor
 */
IntelHexSection::~IntelHexSection()
{

}

/**
 * operator <
 */
bool IntelHexSection::operator<(const IntelHexSection &a) const
{
	return address < a.address;
}

/**
 * Constructor
 */
IntelHexParser::IntelHexParser() :
	mode(true),
	hasEP(false),
	upperAddress(0),
	segmenetAddress(0),
	EIP(0),
	CS(0),
	IP(0),
	actualAddress(0),
	index(0)
{
	actualSection.address = 0;
}

/**
 * Destructor
 */
IntelHexParser::~IntelHexParser()
{

}

/**
 * Parsing
 * @return @c true on success, @c false otherwise
 */
bool IntelHexParser::parse()
{
	index = 0;
	IntelHexToken token;

	while(true)
	{
		token = tokenizer.getToken();
		switch(token.recordType)
		{
			case IntelHexToken::REC_TYPE::RT_DATA:
				handleData(token);
				break;
			case IntelHexToken::REC_TYPE::RT_EXT_LINADDR:
				setOffset(token);
				break;
			case IntelHexToken::REC_TYPE::RT_EXT_SEGADDR:
				setSegment(token);
				break;
			case IntelHexToken::REC_TYPE::RT_START_LINADDR:
				setEIP(token);
				break;
			case IntelHexToken::REC_TYPE::RT_START_SEGADDR:
				setCSIP(token);
				break;
			case IntelHexToken::REC_TYPE::RT_EOFILE:
				sections.push_back(actualSection);
				return true;
			case IntelHexToken::REC_TYPE::RT_ERROR:
			default:
				errorDesc = token.errorDesc;
				return false;
		}
	}

	return true;
}

/**
 * Parse data Intel HEX data record
 * @param token Data token received from tokenizer
 */
void IntelHexParser::handleData(const IntelHexToken &token)
{
	retdec::utils::Address address = 0;
	// 32bit mode
	if(mode)
	{
		address = upperAddress;
		address = address << 16;
		address = address | IntelHexParser::strToInt(token.address);
	}
	// 8086 real mode
	else
	{
		address = segmenetAddress;
		address = address * 16;
		address = address + IntelHexParser::strToInt(token.address);
	}

	const int diff = address - (actualAddress - 1);
	if(diff == 1)
	{
		// Still the same section
		for(std::vector<int>::size_type i = 0; i < token.data.size(); i += 2)
		{
			// Size of vector is always even
			std::string tmp;
			tmp.push_back(token.data[i]);
			tmp.push_back(token.data[i+1]);
			actualSection.data.push_back(IntelHexParser::strToInt(tmp));
			actualAddress += 1;
		}
	}
	else
	{
		// New section
		if(actualAddress)
		{
			sections.push_back(actualSection);
			++index;
		}

		actualAddress = address;
		actualSection.address = address;
		actualSection.index = index;
		actualSection.data.clear();

		for(std::vector<int>::size_type i = 0; i < token.data.size(); i += 2)
		{
			std::string tmp;
			tmp.push_back(token.data[i]);
			tmp.push_back(token.data[i+1]);
			actualSection.data.push_back(IntelHexParser::strToInt(tmp));
			actualAddress += 1;
		}
	}
}

/**
 * Sets new address offset value
 * @param token Extended address token
 */
void IntelHexParser::setOffset(const IntelHexToken &token)
{
	mode = true;
	upperAddress = IntelHexParser::strToInt(token.data);
}

/**
 * Sets new segment value
 * @param token Segment info token
 */
void IntelHexParser::setSegment(const IntelHexToken &token)
{
	mode = false;
	segmenetAddress = IntelHexParser::strToInt(token.data);
}

/**
 * Sets value of entry point
 * @param token EIP token
 */
void IntelHexParser::setEIP(const IntelHexToken &token)
{
	hasEP = true;
	EIP = IntelHexParser::strToInt(token.data);
}

/**
 * Sets value of entry point
 * @param token CS:IP token
 */
void IntelHexParser::setCSIP(const IntelHexToken &token)
{
	std::string first;

	for(unsigned i = 0; i < 4; ++i)
	{
		first.push_back(token.data[i]);
	}

	std::string second;

	for(unsigned i = 4; i < 8; ++i)
	{
		second.push_back(token.data[i]);
	}

	hasEP = true;
	CS = IntelHexParser::strToInt(first);
	IP = IntelHexParser::strToInt(second);
}

/**
 * Parse Intel HEX
 * @param pathToFile Path to input Intel HEX file
 * @return @c true on success, @c false otherwise
 */
bool IntelHexParser::parseFile(const std::string &pathToFile)
{
	if(!tokenizer.openFile(pathToFile))
	{
		errorDesc = "Unable to open file.";
		return false;
	}

	return parse();
}

/**
 * Parse Intel HEX
 * @param inputStream Reference to istream to parse
 * @return @c true on success, @c false otherwise
 */
bool IntelHexParser::parseStream(std::istream &inputStream)
{
	if(!tokenizer.setInputStream(inputStream))
	{
		errorDesc = "Unable to load stream.";
		return false;
	}

	return parse();
}

/**
 * Check if entry point record is in input file
 * @return @c true if entry point record is in input file, @c false otherwise
 */
bool IntelHexParser::hasEntryPoint() const
{
	return hasEP;
}

/**
 * Get entry point
 * @return Entry point
 */
unsigned long long IntelHexParser::getEntryPoint() const
{
	if(EIP)
	{
		return static_cast<unsigned long long>(EIP);
	}

	return static_cast<unsigned long long>(CS * 16 + IP);
}

/**
 * Divide sections to more sections by chosen alignment.
 * Function won't affect original vector.
 * @param alignByValue size of alignment blocks (default 0x10000)
 * @return Result sections
 */
std::vector<IntelHexSection> IntelHexParser::getSectionsByAlignment(unsigned long long alignByValue)
{
	assert(alignByValue != 0);

	unsigned long long index = 0;
	std::vector<IntelHexSection> result;

	for(auto section : sections)
	{
		unsigned long long upperBorder = section.address + section.data.size();
		unsigned long long nearestMult = (section.address / alignByValue + 1) * alignByValue;

		if(nearestMult > upperBorder)
		{
			section.index = index;
			result.push_back(section);
			++index;
		}
		else
		{
			std::vector<unsigned char> tmp;
			unsigned long long diff = upperBorder - nearestMult;

			for(auto i = section.data.size() - diff; i < section.data.size(); ++i)
			{
				tmp.push_back(section.data[i]);
			}

			for(unsigned long long i = 0; i < diff; ++i)
			{
				section.data.pop_back();
			}

			section.index = index;
			result.push_back(section);
			++index;

			section.data = tmp;
			section.index = index;
			section.address = nearestMult;
			result.push_back(section);
			++index;
		}
	}

	return result;
}

/**
 * Converts hexadecimal characters to integer
 * @param str String of chars to convert
 * @return Decimal value
 *
 * @warning No validity control, use only on valid data
 */
unsigned long long IntelHexParser::strToInt(const std::string &str)
{
	unsigned long long res = 0;
	strToNum(str, res, std::hex);
	return res;
}

/**
 * Checks whether character is hexadecimal digit
 * @param c Character to check
 * @return @c true if @a c is hexadecimal ASCII digit, @c false otherwise
 */
bool IntelHexParser::isHexadec(char c)
{
	return ((c >= '0' && c <= '9') ||
		(c >= 'a' && c <= 'f') ||
		(c >= 'A' && c <= 'F'));
}

/**
 * Checks whether characters are hexadecimal digits
 * @param vec Vector of characters to check
 * @return @c true if @a vec contains only hexadecimal ASCII digits
 */
bool IntelHexParser::isHexadec(const std::string &vec)
{
	for(char c : vec)
	{
		if(!IntelHexParser::isHexadec(c))
		{
			return false;
		}
	}

	return true;
}

} // namespace fileformat
} // namespace retdec
