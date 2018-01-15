/**
 * @file src/fileinfo/file_information/file_information_types/relocation_table/relocation.h
 * @brief Class for one relocation.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_RELOCATION_TABLE_RELOCATION_H
#define FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_RELOCATION_TABLE_RELOCATION_H

#include <string>

namespace fileinfo {

/**
 * Class for one relocation
 *
 * Value std::numeric_limits<unsigned long long>::max() mean unspecified value or error for unsigned integer types.
 * Value std::numeric_limits<long long>::min() mean unspecified value or error for signed integer types.
 */
class Relocation
{
	private:
		std::string symbolName;            ///< name of associated symbol
		unsigned long long offset;         ///< relocation offset
		unsigned long long symbolValue;    ///< value of associated symbol
		unsigned long long relocationType; ///< type of relocation
		long long addend;                  ///< relocation addend
		long long calculatedValue;         ///< calculated value of relocation
	public:
		Relocation();
		~Relocation();

		/// @name Getters
		/// @{
		std::string getSymbolName() const;
		std::string getOffsetStr(std::ios_base &(* format)(std::ios_base &)) const;
		std::string getSymbolValueStr() const;
		std::string getRelocationTypeStr() const;
		std::string getAddendStr() const;
		std::string getCalculatedValueStr() const;
		/// @}

		/// @name Setters
		/// @{
		void setSymbolName(std::string name);
		void setOffset(unsigned long long value);
		void setSymbolValue(unsigned long long value);
		void setRelocationType(unsigned long long type);
		void setAddend(long long value);
		void setCalculatedValue(long long value);
		/// @}
};

} // namespace fileinfo

#endif
