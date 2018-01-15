/**
 * @file include/retdec/fileformat/types/symbol_table/symbol.h
 * @brief Class for one symbol.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_SYMBOL_TABLE_SYMBOL_H
#define RETDEC_FILEFORMAT_TYPES_SYMBOL_TABLE_SYMBOL_H

#include <string>

namespace retdec {
namespace fileformat {

/**
 * Class for one symbol
 */
class Symbol
{
	public:
		enum class Type
		{
			UNDEFINED_SYM, ///< invalid type
			PRIVATE,       ///< local
			PUBLIC,        ///< public global symbol
			WEAK,          ///< weak, may be replaced with another symbol
			EXTERN,        ///< expected to be defined in another module
			ABSOLUTE_SYM,  ///< not linked to a section
			COMMON         ///< common
		};

		enum class UsageType
		{
			UNKNOWN,
			FUNCTION,
			OBJECT,
			FILE
		};
	private:
		std::string name;                 ///< symbol name (normalized name)
		std::string originalName;         ///< original name of symbol
		Type type;                        ///< symbol type
		UsageType usageType;              ///< usage of symbol
		unsigned long long index;         ///< symbol index
		unsigned long long address;       ///< virtual address of symbol
		unsigned long long size;          ///< size of symbol
		unsigned long long linkToSection; ///< link to section
		bool addressIsValid;              ///< @c true if value of virtual address is valid
		bool sizeIsValid;                 ///< @c true if size of symbol is valid
		bool linkIsValid;                 ///< @c true if link to section is valid
		bool thumbSymbol;                 ///< @c true if symbol is THUMB symbol
	public:
		Symbol();
		virtual ~Symbol();

		/// @name Type queries
		/// @{
		bool isUndefined() const;
		bool isPrivate() const;
		bool isPublic() const;
		bool isWeak() const;
		bool isExtern() const;
		bool isAbsolute() const;
		bool isCommon() const;
		/// @}

		/// @name Usage type queries
		/// @{
		bool isUnknown() const;
		bool isFunction() const;
		bool isObject() const;
		bool isFile() const;
		/// @}

		/// @name Other queries
		/// @{
		bool isThumbSymbol() const;
		bool isEven() const;
		bool isOdd() const;
		bool hasEmptyName() const;
		/// @}

		/// @name Getters
		/// @{
		const std::string &getName() const;
		std::string getNormalizedName() const;
		std::string getOriginalName() const;
		Symbol::Type getType() const;
		Symbol::UsageType getUsageType() const;
		unsigned long long getIndex() const;
		bool getAddress(unsigned long long &virtualAddress) const;
		bool getRealAddress(unsigned long long &virtualAddress) const;
		bool getSize(unsigned long long &symbolSize) const;
		bool getLinkToSection(unsigned long long &sectionIndex) const;
		/// @}

		/// @name Setters
		/// @{
		void setName(std::string symbolName);
		void setOriginalName(std::string symbolOriginalName);
		void setType(Symbol::Type symbolType);
		void setUsageType(Symbol::UsageType symbolUsageType);
		void setIndex(unsigned long long symbolIndex);
		void setAddress(unsigned long long symbolAddress);
		void setSize(unsigned long long symbolSize);
		void setLinkToSection(unsigned long long sectionIndex);
		void setIsThumbSymbol(bool b);
		/// @}

		/// @name Other methods
		/// @{
		void invalidateAddress();
		void invalidateSize();
		void invalidateLinkToSection();
		/// @}
};

} // namespace fileformat
} // namespace retdec

#endif
