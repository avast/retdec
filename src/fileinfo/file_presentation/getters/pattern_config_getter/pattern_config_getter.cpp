/**
 * @file src/fileinfo/file_presentation/getters/pattern_config_getter/pattern_config_getter.cpp
 * @brief Methods of PatternConfigGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "fileinfo/file_presentation/getters/pattern_config_getter/pattern_config_getter.h"

using namespace retdec::config;

namespace fileinfo {

/**
 * Constructor
 * @param pFileinfo Information about detected patterns
 * @param pOutDoc Output config file
 */
PatternConfigGetter::PatternConfigGetter(const FileInformation &pFileinfo, retdec::config::Config *pOutDoc) :
	fileinfo(pFileinfo), outDoc(pOutDoc), allocate(!pOutDoc), empty(true)
{
	if(allocate)
	{
		outDoc = new Config();
	}

	process();
}

/**
 * Destructor
 */
PatternConfigGetter::~PatternConfigGetter()
{
	if(allocate)
	{
		delete outDoc;
	}
}

/**
 * Process detected patterns and add them to JSON config
 */
void PatternConfigGetter::process()
{
	outDoc->patterns.clear();
	std::size_t i = 0;

	for(const auto &patterns : {fileinfo.getCryptoPatterns(), fileinfo.getMalwarePatterns(), fileinfo.getOtherPatterns()})
	{
		for(const auto &pattern : patterns)
		{
			empty = false;
			auto conPattern = retdec::config::Pattern();
			conPattern.matches.clear();
			conPattern.setName(pattern.getName());
			conPattern.setDescription(pattern.getDescription());
			conPattern.setYaraRuleName(pattern.getYaraRuleName());
			if(pattern.isLittle())
			{
				conPattern.setIsEndianLittle();
			}
			else if(pattern.isBig())
			{
				conPattern.setIsEndianBig();
			}

			switch(i)
			{
				case 0:
					conPattern.setIsTypeCrypto();
					break;
				case 1:
					conPattern.setIsTypeMalware();
					break;
				case 2:
				default:
					conPattern.setIsTypeOther();
			}

			for(const auto &match : pattern.getMatches())
			{
				auto cm = retdec::config::Pattern::Match();
				unsigned long long res;
				if(match.getOffset(res))
				{
					cm.setOffset(res);
				}
				if(match.getAddress(res))
				{
					cm.setAddress(res);
				}
				if(match.getDataSize(res))
				{
					cm.setSize(res);
				}
				if(match.getEntrySize(res))
				{
					cm.setEntrySize(res);
				}
				if(match.isInteger())
				{
					cm.setIsTypeIntegral();
				}
				if(match.isFloatingPoint())
				{
					cm.setIsTypeFloatingPoint();
				}
				conPattern.matches.insert(cm);
			}

			outDoc->patterns.insert(conPattern);
		}

		++i;
	}
}

/**
 * Check if at least one pattern was detected
 * return @c false if at least one pattern was detected, @c true otherwise
 */
bool PatternConfigGetter::isEmpty() const
{
	return empty;
}

/**
 * Get JSON value of detected patterns
 * @return JSON value of detected patterns
 */
Json::Value PatternConfigGetter::getJsonValue() const
{
	return outDoc->patterns.getJsonValue();
}

} // namespace fileinfo
