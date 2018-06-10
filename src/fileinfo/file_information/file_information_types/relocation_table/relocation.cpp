/**
 * @file src/fileinfo/file_information/file_information_types/relocation_table/relocation.cpp
 * @brief Class for one relocation.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_information/file_information_types/relocation_table/relocation.h"
#include "fileinfo/file_information/file_information_types/type_conversions.h"

namespace fileinfo {

/**
 * Constructor
 */
Relocation::Relocation() : offset(std::numeric_limits<unsigned long long>::max()),
							symbolValue(std::numeric_limits<unsigned long long>::max()),
							relocationType(std::numeric_limits<unsigned long long>::max()),
							addend(std::numeric_limits<long long>::min()),
							calculatedValue(std::numeric_limits<long long>::min())
{

}

/**
 * Destructor
 */
Relocation::~Relocation()
{

}

/**
 * Get name of associated symbol
 * @return Name of associated symbol
 */
std::string Relocation::getSymbolName() const
{
	return symbolName;
}

/**
 * Get relocation offset
 * @param format Format of result (e.g. std::dec, std::hex)
 * @return Relocation offset
 */
std::string Relocation::getOffsetStr(std::ios_base &(* format)(std::ios_base &)) const
{
	return getNumberAsString(offset, format);
}

/**
 * Get value of associated symbol
 * @return Value of associated symbol
 */
std::string Relocation::getSymbolValueStr() const
{
	return getNumberAsString(symbolValue);
}

/**
 * Get relocation type
 * @return Type of relocation
 */
std::string Relocation::getRelocationTypeStr() const
{
	return getNumberAsString(relocationType);
}

/**
 * Get relocation addend
 * @return Relocation addend
 */
std::string Relocation::getAddendStr() const
{
	return getNumberAsString(addend);
}

/**
 * Get calculated value
 * @return Calculated value
 */
std::string Relocation::getCalculatedValueStr() const
{
	return getNumberAsString(calculatedValue);
}

/**
 * Set name of associated symbol
 * @param name Name of symbol associated with relocation
 */
void Relocation::setSymbolName(std::string name)
{
	symbolName = name;
}

/**
 * Set relocation offset
 * @param value Relocation offset
 */
void Relocation::setOffset(unsigned long long value)
{
	offset = value;
}

/**
 * Set value of symbol associated with relocation
 * @param value Value of symbol associated with relocation
 */
void Relocation::setSymbolValue(unsigned long long value)
{
	symbolValue = value;
}

/**
 * Set type of relocation
 * @param type Type of relocation
 */
void Relocation::setRelocationType(unsigned long long type)
{
	relocationType = type;
}

/**
 * Set relocation addend
 * @param value Relocation addend
 */
void Relocation::setAddend(long long value)
{
	addend = value;
}

/**
 * Set calculated value
 * @param value Calculated value
 */
void Relocation::setCalculatedValue(long long value)
{
	calculatedValue = value;
}

} // namespace fileinfo
