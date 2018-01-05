/**
 * @file src/fileformat/types/relocation_table/relocation.cpp
 * @brief Class for one relocation.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/types/relocation_table/relocation.h"

namespace retdec {
namespace fileformat {

/**
 * Constructor
 */
Relocation::Relocation() : address(0), offsetInSection(0), linkToSection(0),
	addend(0), type(0), linkToSectionIsValid(false), linkToSymbolIsValid(false)
{

}

/**
 * Destructor
 */
Relocation::~Relocation()
{

}

/**
 * Get name of relocation
 * @return Relocation name
 */
std::string Relocation::getName() const
{
	return name;
}

/**
 * Get address at which to apply the relocation
 * @return Address at which to apply the relocation
 */
unsigned long long Relocation::getAddress() const
{
	return address;
}

/**
 * Get offset of relocation in section at which relocation is applied
 * @return Offset of relocation
 */
unsigned long long  Relocation::getSectionOffset() const
{
	return offsetInSection;
}

/**
 * Get link to section at which relocations are applied
 * @param sectionIndex Parameter for store the result
 * @return @c true if link to section is valid, @c false otherwise
 *
 * If method returns @c false, @a sectionIndex is left unchanged
 */
bool Relocation::getLinkToSection(unsigned long long &sectionIndex) const
{
	if(linkToSectionIsValid)
	{
		sectionIndex = linkToSection;
	}

	return linkToSectionIsValid;
}

/**
 * Get link to symbol which is used for relocation calculation
 * @param symbolIndex Parameter for store the result
 * @return @c true if link to symbol is valid, @c false otherwise
 *
 * If method returns @c false, @a symbolIndex is left unchanged
 */
bool Relocation::getLinkToSymbol(unsigned long long &symbolIndex) const
{
	if (linkToSymbolIsValid)
	{
		symbolIndex = linkToSymbol;
	}

	return linkToSymbolIsValid;
}

/**
 * Get addend of relocation
 * @return Addend of the relocation
 */
unsigned long long Relocation::getAddend() const
{
	return addend;
}

/**
 * Get type of relocation
 * @return Type of relocation
 */
unsigned long long Relocation::getType() const
{
	return type;
}

/**
 * Get relocation mask
 * @return Relocation mask as vector of mask bytes
 */
std::vector<std::uint8_t> Relocation::getMask() const
{
	return mask;
}

/**
 * Set relocation name
 * @param relocationName Name of relocation
 */
void Relocation::setName(std::string relocationName)
{
	name = relocationName;
}

/**
 * Set address at which to apply the relocation
 * @param relocationAddress Address at which to apply the relocation
 */
void Relocation::setAddress(unsigned long long relocationAddress)
{
	address = relocationAddress;
}

/**
 * Set offset in section at which relocation is applied
 * @param relocationOffsetInSection Offset in section at which relocation is applied
 */
void Relocation::setSectionOffset(unsigned long long relocationOffsetInSection)
{
	offsetInSection = relocationOffsetInSection;
}

/**
 * Set link to section at which relocation is applied
 * @param relocationLinkToSection Link to section at which relocation is applied
 */
void Relocation::setLinkToSection(unsigned long long relocationLinkToSection)
{
	linkToSection = relocationLinkToSection;
	linkToSectionIsValid = true;
}

/**
 * Set link to symbol which is used for relocation calculation
 * @param relocationLinkToSymbol Link to symbol
 */
void Relocation::setLinkToSymbol(unsigned long long relocationLinkToSymbol)
{
	linkToSymbol = relocationLinkToSymbol;
	linkToSymbolIsValid = true;
}

/**
 * Set relocation addend
 * @param relocationAddend Addend of the relocation
 */
void Relocation::setAddend(unsigned long long relocationAddend)
{
	addend = relocationAddend;
}

/**
 * Set type of relocation
 * @param relocationType Type of relocation
 */
void Relocation::setType(unsigned long long relocationType)
{
	type = relocationType;
}

/**
 * Set relocation mask
 * @param relocationMask Relocation mask as vector of mask bytes
 */
void Relocation::setMask(const std::vector<std::uint8_t> &relocationMask)
{
	mask = relocationMask;
}

/**
 * Invalidate link to section
 *
 * Instance method @a getLinkToSection() returns @c false after invocation
 * of this method. Link to section is possible to revalidate by invocation
 * of method @a setLinkToSection().
 */
void Relocation::invalidateLinkToSection()
{
	linkToSectionIsValid = false;
}

/**
 * Invalidate link to symbol
 *
 * Instance method @a getLinkToSymbol() returns @c false after invocation
 * of this method. Link to symbol is possible to revalidate by invocation
 * of method @a setLinkToSymbol().
 */
void Relocation::invalidateLinkToSymbol()
{
	linkToSymbolIsValid = false;
}

/**
 * @return @c true if relocation has empty name, @c false otherwise
 */
bool Relocation::hasEmptyName() const
{
	return name.empty();
}

} // namespace fileformat
} // namespace retdec
