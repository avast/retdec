/**
 * @file src/fileinfo/file_information/file_information_types/symbol_table/symbol.h
 * @brief Class for one symol.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_SYMBOL_TABLE_SYMBOL_H
#define FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_SYMBOL_TABLE_SYMBOL_H

#include <limits>
#include <string>

namespace retdec {
namespace fileinfo {

/**
 * Class for one symbol
 *
 * Value std::numeric_limits<unsigned long long>::max() mean unspecified value or error for numeric types.
 */
class Symbol
{
	private:
		std::string name;           ///< name of symbol
		std::string type;           ///< type of symbol
		std::string bind;           ///< symbol bind
		std::string other;          ///< other information
		std::string linkToSection;  ///< link to associated section
		unsigned long long index = std::numeric_limits<unsigned long long>::max();   ///< index of symbol in symbol table
		unsigned long long value = std::numeric_limits<unsigned long long>::max();   ///< value of symbol
		unsigned long long address = std::numeric_limits<unsigned long long>::max(); ///< symbol address
		unsigned long long size = std::numeric_limits<unsigned long long>::max();    ///< size associated with symbol
	public:
		/// @name Getters
		/// @{
		std::string getName() const;
		std::string getType() const;
		std::string getBind() const;
		std::string getOther() const;
		std::string getLinkToSection() const;
		std::string getIndexStr() const;
		std::string getValueStr() const;
		std::string getAddressStr(std::ios_base &(* format)(std::ios_base &)) const;
		std::string getSizeStr() const;
		/// @}

		/// @name Setters
		/// @{
		void setName(std::string symbolName);
		void setType(std::string symbolType);
		void setBind(std::string symbolBind);
		void setOther(std::string otherInformation);
		void setLinkToSection(std::string link);
		void setIndex(unsigned long long symbolIndex);
		void setValue(unsigned long long symbolValue);
		void setAddress(unsigned long long addressValue);
		void setSize(unsigned long long symbolSize);
		/// @}
};

} // namespace fileinfo
} // namespace retdec

#endif
