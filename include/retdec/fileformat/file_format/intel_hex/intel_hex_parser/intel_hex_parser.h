/**
 * @file include/retdec/fileformat/file_format/intel_hex/intel_hex_parser/intel_hex_parser.h
 * @brief Definition of IntelHexSection and IntelHexParser classes.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_FILE_FORMAT_INTEL_HEX_INTEL_HEX_PARSER_INTEL_HEX_PARSER_H
#define RETDEC_FILEFORMAT_FILE_FORMAT_INTEL_HEX_INTEL_HEX_PARSER_INTEL_HEX_PARSER_H

#include <fstream>
#include <iostream>
#include <vector>

#include "retdec/utils/address.h"
#include "retdec/fileformat/file_format/intel_hex/intel_hex_parser/intel_hex_tokenizer.h"

namespace retdec {
namespace fileformat {

/**
 * @brief The IntelHexSection class - Intel HEX pseudosection
 */
class IntelHexSection
{
	public:
		unsigned long long index = 0;
		retdec::utils::Address address;
		std::vector<unsigned char> data;

		IntelHexSection();
		~IntelHexSection();

		/// @name Operators
		/// @{
		bool operator<(IntelHexSection const &a) const;
		/// @}
};

/**
 * @brief The IntelHexParser class - Intel HEX semantical analysis
 */
class IntelHexParser
{
	private:
		IntelHexTokenizer tokenizer;           ///< Tokenizer
		bool mode;                             ///< @c true when 32bit address mode, @c false when 20bit segment mode
		bool hasEP;                            ///< @c true if entry point record is in file
		std::uint16_t upperAddress;            ///< Upper 16bits of 32bit address
		std::uint16_t segmenetAddress;         ///< Segment address
		std::uint32_t EIP;                     ///< Entry point (EIP register)
		std::uint16_t CS;                      ///< Entry point segment (CS register)
		std::uint16_t IP;                      ///< Entry point instruction (IP register)
		IntelHexSection actualSection;         ///< Actual section (one section may be constructed from more than one record)
		retdec::utils::Address actualAddress; ///< Address of last byte saved to actual section
		unsigned long long index;              ///< Indexing
	public:
		std::string errorDesc;                 ///< Error description
		std::vector<IntelHexSection> sections; ///< Sections (access after methods parseFile() or parseStream() only)
	private:
		/// @name Private parsing methods
		/// @{
		bool parse();
		void handleData(const IntelHexToken &token);
		void setOffset(const IntelHexToken &token);
		void setSegment(const IntelHexToken &token);
		void setEIP(const IntelHexToken &token);
		void setCSIP(const IntelHexToken &token);
		/// @}
	public:
		IntelHexParser();
		~IntelHexParser();

		/// @name Public parsing methods
		/// @{
		bool parseFile(const std::string &pathToFile);
		bool parseStream(std::istream &inputStream);
		/// @}

		/// @name Getters
		/// @{
		bool hasEntryPoint() const;
		unsigned long long getEntryPoint() const;
		std::vector<IntelHexSection> getSectionsByAlignment(unsigned long long alignByValue = 0x10000);
		/// @}

		/// @name Hexadecimal conversions
		/// @{
		static unsigned long long strToInt(const std::string &str);
		static bool isHexadec(char c);
		static bool isHexadec(const std::string &vec);
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
