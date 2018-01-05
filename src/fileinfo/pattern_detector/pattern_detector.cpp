/**
 * @file src/fileinfo/pattern_detector/pattern_detector.cpp
 * @brief Methods of PatternDetector class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <regex>

#include "retdec/utils/conversion.h"
#include "retdec/utils/filesystem_path.h"
#include "retdec/utils/string.h"
#include "fileinfo/pattern_detector/pattern_detector.h"

using namespace retdec::utils;
using namespace yaracpp;

namespace fileinfo {

/**
 * Constructor
 * @param fparser Pointer to file parser
 * @param finfo Reference to information about input file
 */
PatternDetector::PatternDetector(const retdec::fileformat::FileFormat *fparser, FileInformation &finfo) :
	fileParser(fparser), fileinfo(finfo)
{

}

/**
 * Destructor
 */
PatternDetector::~PatternDetector()
{

}

/**
 * Get begin iterator
 * @return Begin iterator
 */
PatternDetector::patternCategoriesIterator PatternDetector::begin() const
{
	return categories.begin();
}

/**
 * Get end iterator
 * @return End iterator
 */
PatternDetector::patternCategoriesIterator PatternDetector::end() const
{
	return categories.end();
}

/**
 * Create pattern from YARA rule
 * @param pattern Into this parameter is stored resulted pattern
 * @param rule Detected YARA rule
 */
void PatternDetector::createPatternFromRule(Pattern &pattern, const yaracpp::YaraRule &rule)
{
	const auto name = rule.getName();
	pattern.setName(name);
	pattern.setYaraRuleName(name);
	const auto *descMeta = rule.getMeta("description");
	if(!descMeta)
	{
		descMeta = rule.getMeta("desc");
	}
	pattern.setDescription(descMeta ? descMeta->getStringValue() : name);
	if(fileParser && fileParser->isInValidState())
	{
		if(fileParser->isLittleEndian())
		{
			pattern.setLittle();
		}
		else if(fileParser->isBigEndian())
		{
			pattern.setBig();
		}
	}

	for(std::size_t i = 0, e = rule.getNumberOfMatches(); i < e; ++i)
	{
		const auto *match = rule.getMatch(i);
		if(!match)
		{
			continue;
		}
		PatternMatch patMatch;
		patMatch.setDataSize(match->getDataSize());
		patMatch.setOffset(match->getOffset());
		unsigned long long val;
		if(fileParser && fileParser->getAddressFromOffset(val, match->getOffset()))
		{
			patMatch.setAddress(val);
		}
		pattern.addMatch(patMatch);
	}
}

/**
 * Save detected cryptography rule
 * @param rule Detected cryptography rule
 */
void PatternDetector::saveCryptoRule(const yaracpp::YaraRule &rule)
{
	const auto name = rule.getName();
	Pattern pattern;
	pattern.setYaraRuleName(name);
	pattern.setName(name);
	const auto *descMeta = rule.getMeta("description");
	if(!descMeta)
	{
		descMeta = rule.getMeta("desc");
	}
	pattern.setDescription(descMeta ? descMeta->getStringValue() : name);
	std::smatch rMatch, rMatchFlt;
	bool isInt = false, isFlt = false, entrySize = false;
	if(regex_search(name, rMatch, std::regex("__([0-9]+)_(big|lil|byt)_")))
	{
		entrySize = true;
		if(rMatch[2] == "lil")
		{
			pattern.setLittle();
		}
		else if(rMatch[2] == "big")
		{
			pattern.setBig();
		}

		if(regex_search(name, rMatchFlt, std::regex("__flt([0-9]+)___")))
		{
			isFlt = true;
			pattern.setName(rMatchFlt.prefix());
			if(!descMeta)
			{
				pattern.setDescription(rMatchFlt.prefix());
			}
		}
		else
		{
			isInt = true;
			pattern.setName(rMatch.prefix());
			if(!descMeta)
			{
				pattern.setDescription(rMatch.prefix());
			}
		}
	}

	if(!pattern.isLittle() && !pattern.isBig() && fileParser && fileParser->isInValidState())
	{
		if(fileParser->isLittleEndian())
		{
			pattern.setLittle();
		}
		else if(fileParser->isBigEndian())
		{
			pattern.setBig();
		}
	}

	std::string descInfo;
	unsigned long long entrySizeValue = 0;
	if(entrySize && rMatch.size() > 1 && strToNum(rMatch[1], entrySizeValue, std::dec))
	{
		descInfo.push_back('(');
		descInfo += rMatch[1];
		descInfo += "-bit";
	}
	else
	{
		entrySize = false;
	}

	if(pattern.isLittle() || pattern.isBig())
	{
		if(descInfo.empty())
		{
			descInfo.push_back('(');
		}
		else
		{
			descInfo += ", ";
		}
		descInfo += (pattern.isLittle() ? "little" : "big");
		descInfo += " endian";
	}

	if(!descInfo.empty())
	{
		if(descInfo[0] == '(')
		{
			descInfo.push_back(')');
		}
		pattern.setDescription(pattern.getDescription() + " " + descInfo);
	}

	for(std::size_t i = 0, e = rule.getNumberOfMatches(); i < e; ++i)
	{
		const auto *match = rule.getMatch(i);
		if(!match)
		{
			continue;
		}
		PatternMatch patMatch;
		if(isFlt)
		{
			patMatch.setFloatingPoint();
		}
		else if(isInt)
		{
			patMatch.setInteger();
		}
		patMatch.setDataSize(match->getDataSize());

		if(entrySize)
		{
			std::size_t byteLen = 0;
			if(fileParser && fileParser->isInValidState())
			{
				byteLen = fileParser->getByteLength();
				if(!byteLen)
				{
					if(fileinfo.getFileClass() == "8-bit")
					{
						byteLen = 1;
					}
					else if(fileinfo.getFileClass() == "16-bit")
					{
						byteLen = 2;
					}
					else if(fileinfo.getFileClass() == "32-bit")
					{
						byteLen = 4;
					}
					else if(fileinfo.getFileClass() == "64-bit")
					{
						byteLen = 8;
					}
					else if(fileinfo.getFileClass() == "128-bit")
					{
						byteLen = 16;
					}
					else if(fileinfo.getFileClass() == "256-bit")
					{
						byteLen = 32;
					}
				}
			}
			if(byteLen)
			{
				patMatch.setEntrySize(entrySizeValue / byteLen);
			}
		}
		patMatch.setOffset(match->getOffset());
		unsigned long long val = 0;
		if(fileParser && fileParser->getAddressFromOffset(val, match->getOffset()))
		{
			patMatch.setAddress(val);
		}
		pattern.addMatch(patMatch);
	}

	fileinfo.addCryptoPattern(pattern);
}

/**
 * Save detected cryptography rule
 * @param rule Detected cryptography rule
 */
void PatternDetector::saveMalwareRule(const yaracpp::YaraRule &rule)
{
	Pattern pattern;
	createPatternFromRule(pattern, rule);
	fileinfo.addMalwarePattern(pattern);
}

/**
 * Save detected cryptography rule
 * @param rule Detected cryptography rule
 */
void PatternDetector::saveOtherRule(const yaracpp::YaraRule &rule)
{
	Pattern pattern;
	createPatternFromRule(pattern, rule);
	fileinfo.addOtherPattern(pattern);
}

/**
 * Add paths to files with YARA patterns
 * @param category Name of YARA patterns category (e.g. malware, crypto)
 * @param paths Set of paths to files and/or directories with YARA pattern files.
 *    From directory is taken every file with .yar or .yara extension.
 */
void PatternDetector::addFilePaths(const std::string &category, const std::set<std::string> &paths)
{
	const auto tlCategory = toLower(category);
	std::pair<std::string, std::set<std::string>> *actCategory = nullptr;

	for(auto &item : categories)
	{
		if(tlCategory == item.first)
		{
			actCategory = &item;
			break;
		}
	}

	if(!actCategory)
	{
		categories.emplace_back(tlCategory, std::set<std::string>());
		actCategory = &categories[categories.size() - 1];
	}

	for(const auto &item : paths)
	{
		FilesystemPath actDir(item);
		if(actDir.isFile())
		{
			actCategory->second.insert(item);
			continue;
		}

		for(const auto &file : actDir)
		{
			const auto path = file->getPath();
			if(file->isFile() && (endsWith(path, ".yar") || endsWith(path, ".yara")))
			{
				actCategory->second.insert(path);
			}
		}
	}
}

/**
 * Analyze input file and try to find YARA patterns
 */
void PatternDetector::analyze()
{
	for(const auto &category : categories)
	{
		YaraDetector yara;

		for(const auto &item : category.second)
		{
			yara.addRuleFile(item);
		}

		yara.analyze(fileinfo.getPathToFile());

		for(const auto &rule : yara.getDetectedRules())
		{
			if(category.first == "crypto")
			{
				saveCryptoRule(rule);
			}
			else if(category.first == "malware")
			{
				saveMalwareRule(rule);
			}
			else
			{
				saveOtherRule(rule);
			}
		}
	}

	fileinfo.removeRedundantCryptoRules();
	fileinfo.sortCryptoPatternMatches();
	fileinfo.sortMalwarePatternMatches();
	fileinfo.sortOtherPatternMatches();
}

} // namespace fileinfo
