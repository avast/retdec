/**
 * @file include/retdec/cpdetect/compiler_detector/search/search.h
 * @brief Class for search in file.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CPDETECT_COMPILER_DETECTOR_SEARCH_SEARCH_H
#define RETDEC_CPDETECT_COMPILER_DETECTOR_SEARCH_SEARCH_H

#include "retdec/cpdetect/cptypes.h"
#include "retdec/fileformat/file_format/file_format.h"

namespace retdec {
namespace cpdetect {

/**
 * Class for search in file
 */
class Search
{
	public:
		/**
		 * Description of relative jump
		 */
		class RelativeJump
		{
			private:
				std::string slash;      ///< representations of '/' in file
				std::size_t bytesAfter; ///< number of bytes after slash for read
			public:
				RelativeJump(std::string sSlash, std::size_t sBytesAfter);
				~RelativeJump();

				/// @name Jump getters
				/// @{
				std::string getSlash() const;
				std::size_t getSlashNibbleSize() const;
				std::size_t getBytesAfter() const;
				/// @}
		};
	private:
		retdec::fileformat::FileFormat &parser; ///< parser of input file
		std::string nibbles;             ///< content of file in hexadecimal string representation
		std::string plain;               ///< content of file as plain string
		std::vector<RelativeJump> jumps; ///< representation of supported relative jumps
		std::size_t averageSlashLen;     ///< average length of one slash representation
		bool fileLoaded;                 ///< @c true if file was successfully loaded, @c false otherwise
		bool fileSupported;              ///< @c true if search of patterns is supported for input file, @c false otherwise

		/// @name Auxiliary methods
		/// @{
		bool haveSlashes() const;
		std::size_t nibblesFromBytes(std::size_t nBytes) const;
		std::size_t bytesFromNibbles(std::size_t nNibbles) const;
		/// @}
	public:
		Search(retdec::fileformat::FileFormat &fileParser);
		~Search();

		/// @name Status methods
		/// @{
		bool isFileLoaded() const;
		bool isFileSupported() const;
		/// @}

		/// @name Getters
		/// @{
		const std::string& getNibbles() const;
		const std::string& getPlainString() const;
		/// @}

		/// @name Jump methods
		/// @{
		const RelativeJump* getRelativeJump(std::size_t fileOffset, std::size_t shift, std::int64_t &moveSize) const;
		/// @}

		/// @name Search methods based on signatures
		/// @{
		unsigned long long countImpNibbles(const std::string &signPattern) const;
		unsigned long long findUnslashedSignature(const std::string &signPattern, std::size_t startOffset, std::size_t stopOffset) const;
		unsigned long long findSlashedSignature(const std::string &signPattern, std::size_t startOffset, std::size_t stopOffset) const;
		unsigned long long exactComparison(const std::string &signPattern, std::size_t fileOffset, std::size_t shift = 0) const;
		bool countSimilarity(const std::string &signPattern, Similarity &sim, std::size_t fileOffset, std::size_t shift = 0) const;
		bool areaSimilarity(const std::string &signPattern, Similarity &sim, std::size_t startOffset, std::size_t stopOffset) const;
		/// @}

		/// @name Search methods based on plain-string comparison
		/// @{
		bool hasString(const std::string &str) const;
		bool hasString(const std::string &str, std::size_t fileOffset) const;
		bool hasString(const std::string &str, std::size_t startOffset, std::size_t stopOffset) const;
		bool hasStringInSection(const std::string &str, const retdec::fileformat::Section *section) const;
		bool hasStringInSection(const std::string &str, std::size_t sectionIndex) const;
		bool hasStringInSection(const std::string &str, const std::string &sectionName) const;
		/// @}

		/// @name Signature methods
		/// @{
		bool createSignature(std::string &pattern, std::size_t fileOffset, std::size_t size) const;
		/// @}
};

} // namespace cpdetect
} // namespace retdec

#endif
