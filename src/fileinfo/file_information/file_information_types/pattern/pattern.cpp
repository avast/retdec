/**
 * @file src/fileinfo/file_information/file_information_types/pattern/pattern.cpp
 * @brief Information about detected pattern.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_information/file_information_types/pattern/pattern.h"

namespace fileinfo {

/**
 * Constructor
 */
Pattern::Pattern() : little(false), big(false)
{

}

/**
 * Destructor
 */
Pattern::~Pattern()
{

}

/**
 * Check if detected pattern is in little endian
 * @return @c true if detected pattern is in little endian, @c false otherwise
 */
bool Pattern::isLittle() const
{
	return little;
}

/**
 * Check if detected pattern is in big endian
 * @return @c true if detected pattern is in big endian, @c false otherwise
 */
bool Pattern::isBig() const
{
	return big;
}

/**
 * Get name of pattern
 * @return Name of pattern
 */
std::string Pattern::getName() const
{
	return name;
}

/**
 * Get description of pattern
 * @return Description of pattern
 */
std::string Pattern::getDescription() const
{
	return description;
}

/**
 * Get name of YARA rule
 * @return Name of YARA rule
 */
std::string Pattern::getYaraRuleName() const
{
	return yaraRuleName;
}

/**
 * Get number of detected matches
 * @return Number of detected matches
 */
std::size_t Pattern::getNumberOfMatches() const
{
	return matches.size();
}

/**
 * Get selected pattern match
 * @param index Index of selected match (0..x)
 * @return Pointer to selected match or @c nullptr if @a index is out of range
 */
const PatternMatch* Pattern::getMatch(std::size_t index) const
{
	return index < getNumberOfMatches() ? &matches[index] : nullptr;
}

/**
 * Get all matches
 * @return All detected matches
 */
const std::vector<PatternMatch>& Pattern::getMatches() const
{
	return matches;
}

/**
 * Get const begin matches iterator
 */
Pattern::patternMatchConstIterator Pattern::begin() const
{
	return matches.cbegin();
}

/**
 * Get const end matches iterator
 */
Pattern::patternMatchConstIterator Pattern::end() const
{
	return matches.cend();
}

/**
 * Get begin matches iterator
 */
Pattern::patternMatchIterator Pattern::begin()
{
	return matches.begin();
}

/**
 * Get end matches iterator
 */
Pattern::patternMatchIterator Pattern::end()
{
	return matches.end();
}

/**
 * Set name of pattern
 * @param sName Name of pattern
 */
void Pattern::setName(std::string sName)
{
	name = sName;
}

/**
 * Set description of pattern
 * @param sDescription Description of pattern
 */
void Pattern::setDescription(std::string sDescription)
{
	description = sDescription;
}

/**
 * Set name of YARA rule
 * @param sYaraRuleName Name of YARA rule
 */
void Pattern::setYaraRuleName(std::string sYaraRuleName)
{
	yaraRuleName = sYaraRuleName;
}

/**
 * Set little endian
 */
void Pattern::setLittle()
{
	little = true;
	big = false;
}

/**
 * Set little endian
 */
void Pattern::setBig()
{
	little = false;
	big = true;
}

/**
 * Add detected match
 * @param match Detected match
 */
void Pattern::addMatch(PatternMatch &match)
{
	matches.push_back(match);
}

} // namespace fileinfo
