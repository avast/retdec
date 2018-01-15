/**
 * @file src/fileinfo/file_information/file_information_types/pattern/pattern.h
 * @brief Information about detected pattern.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_PATTERN_PATTERN_H
#define FILEINFO_FILE_INFORMATION_FILE_INFORMATION_TYPES_PATTERN_PATTERN_H

#include <string>
#include <vector>

#include "fileinfo/file_information/file_information_types/pattern/pattern_match.h"

namespace fileinfo {

/**
 * Class for information about detected pattern
 */
class Pattern
{
	private:
		using patternMatchConstIterator = std::vector<PatternMatch>::const_iterator;
		using patternMatchIterator = std::vector<PatternMatch>::iterator;
		std::string name;                  ///< name of pattern
		std::string description;           ///< description of pattern
		std::string yaraRuleName;          ///< set name of YARA rule
		bool little;                       ///< @c true if pattern is little endian
		bool big;                          ///< @c true if pattern is big endian
		std::vector<PatternMatch> matches; ///< all matches of pattern
	public:
		Pattern();
		~Pattern();

		/// @name Query methods
		/// @{
		bool isLittle() const;
		bool isBig() const;
		/// @}

		/// @name Getters
		/// @{
		std::string getName() const;
		std::string getDescription() const;
		std::string getYaraRuleName() const;
		std::size_t getNumberOfMatches() const;
		const PatternMatch* getMatch(std::size_t index) const;
		const std::vector<PatternMatch>& getMatches() const;
		/// @}

		/// @name Iterators
		/// @{
		patternMatchConstIterator begin() const;
		patternMatchConstIterator end() const;
		patternMatchIterator begin();
		patternMatchIterator end();
		/// @}

		/// @name Setters
		/// @{
		void setName(std::string sName);
		void setDescription(std::string sDescription);
		void setYaraRuleName(std::string sYaraRuleName);
		void setLittle();
		void setBig();
		/// @}

		/// @name Other methods
		/// @{
		void addMatch(PatternMatch &match);
		/// @}
};

} // namespace fileinfo

#endif
