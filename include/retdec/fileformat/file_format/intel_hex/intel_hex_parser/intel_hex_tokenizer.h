/**
 * @file include/retdec/fileformat/file_format/intel_hex/intel_hex_parser/intel_hex_tokenizer.h
 * @brief Definition of IntelHexToken and IntelHexTokenizer classes.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_FILE_FORMAT_INTEL_HEX_INTEL_HEX_PARSER_INTEL_HEX_TOKENIZER_H
#define RETDEC_FILEFORMAT_FILE_FORMAT_INTEL_HEX_INTEL_HEX_PARSER_INTEL_HEX_TOKENIZER_H

#include <fstream>
#include <string>
#include <vector>

namespace retdec {
namespace fileformat {

/**
 * @brief The Token class - output of tokenizer
 */
class IntelHexToken
{
	public:
		/// Possible Token types.
		struct REC_TYPE
		{
			enum : unsigned
			{
				RT_DATA = 0,
				RT_EOFILE,
				RT_EXT_SEGADDR,
				RT_START_SEGADDR,
				RT_EXT_LINADDR,
				RT_START_LINADDR,
				RT_ERROR
			};
		};

		unsigned byteCount = 0;     ///< Size of data in bytes
		unsigned recordType = 0;    ///< Type of record
		std::string address;        ///< Address of data
		std::string data;           ///< Data
		std::string checksum;       ///< Checksum in ASCII
		std::string errorDesc;      ///< Error description in case of REC_TYPE::RT_ERROR
		bool checksumValid = false; ///< True if checksum is valid. False by default

		IntelHexToken();
		~IntelHexToken();

		/// @name Auxiliary methods
		/// @{
		int addStringByTwo(const std::string &str);
		void controlChecksum();
		/// @}
};

/**
 * @brief The Tokenizer class - Intel HEX lexical analysis
 */
class IntelHexTokenizer
{
	private:
		std::ifstream fstr;
		std::istream *source = nullptr;

		/// @name Helper methods
		/// @{
		std::string readN(unsigned n);
		IntelHexToken makeErrorToken(const std::string &errorMessage);
		/// @}
	public:
		IntelHexTokenizer();
		~IntelHexTokenizer();

		/// @name Getters
		/// @{
		IntelHexToken getToken();
		/// @}

		/// @name Initialization functions
		/// @{
		bool openFile(const std::string &pathToFile);
		bool setInputStream(std::istream &inputStream);
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
