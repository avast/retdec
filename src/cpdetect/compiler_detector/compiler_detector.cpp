/**
 * @file src/cpdetect/compiler_detector/compiler_detector.cpp
 * @brief Methods of CompilerDetector class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "tl-cpputils/conversion.h"
#include "tl-cpputils/equality.h"
#include "tl-cpputils/filesystem_path.h"
#include "tl-cpputils/string.h"
#include "cpdetect/compiler_detector/compiler_detector.h"
#include "cpdetect/settings.h"
#include "cpdetect/utils/version_solver.h"

using namespace fileformat;
using namespace tl_cpputils;
using namespace yaracpp;

namespace cpdetect {

namespace
{

/**
 * Auxiliary function for compilers sort
 */
bool compareForSort(const DetectResult &a, const DetectResult &b)
{
	if(a.strength == b.strength)
	{
		if (a.source == DetectionMethod::SIGNATURE && a.source == b.source)
		{
			// Equaly strong signature detections - check nibble counts
			const auto aRatio = static_cast<double>(a.agreeCount) / a.impCount;
			const auto bRatio = static_cast<double>(b.agreeCount) / b.impCount;
			if (areEqual(aRatio, bRatio))
			{
				if (isShorterPrefixOfCaseInsensitive(a.name, b.name)
						&& a.impCount == b.impCount)
				{
					// Equaly strong detections for one compiler
					if (!a.versionInfo.empty() && b.versionInfo.empty())
					{
						// Prefer detection with version
						return true;
					}
					if (a.versionInfo.empty() && !b.versionInfo.empty())
					{
						// Prefer detection with version
						return false;
					}

					// Equaly strong detections - use additional information
					return a.additionalInfo.length() > b.additionalInfo.length();
				}
				else
				{
					// Prefer bigger signature
					return a.impCount > b.impCount;
				}
			}
			else
			{
				// Prefer better match
				return aRatio > bRatio;
			}
		}

		// Everything is better than incomplete signature detection
		if (b.source == DetectionMethod::SIGNATURE && b.agreeCount != b.impCount)
		{
			return true;
		}
		else if (a.source == DetectionMethod::SIGNATURE && a.agreeCount != a.impCount)
		{
			return false;
		}

		// If both are same compilers with same detection strength
		if (isShorterPrefixOfCaseInsensitive(a.name, b.name))
		{
			// Equaly strong detections for one compiler
			if (!a.versionInfo.empty() && b.versionInfo.empty())
			{
				// Prefer detection with version
				return true;
			}
			if (a.versionInfo.empty() && !b.versionInfo.empty())
			{
				// Prefer detection with version
				return false;
			}

			// If at least one detection has version
			if (!a.additionalInfo.empty() || !b.additionalInfo.empty())
			{
				return a.additionalInfo.length() > b.additionalInfo.length();
			}
		}

		// Prefer heuristic
		return b.source == DetectionMethod::SIGNATURE;
	}

	// Prefer stronger method
	return a.strength > b.strength;
}

/**
 * Convert meta to type of tool.
 */
ToolType metaToTool(const std::string &toolMeta)
{
	if (toolMeta == "C")
	{
		return ToolType::COMPILER;
	}
	if (toolMeta == "P")
	{
		return ToolType::PACKER;
	}
	if (toolMeta == "L")
	{
		return ToolType::LINKER;
	}
	if (toolMeta == "I")
	{
		return ToolType::INSTALLER;
	}

	return ToolType::UNKNOWN;
}

} // anonymous namespace

/**
 * Constructor
 *
 * Constructor in subclass must create members @a heuristics, @a internalDatabase and @a externalSuffixes
 */
CompilerDetector::CompilerDetector(fileformat::FileFormat &parser, DetectParams &params, ToolInformation &toolInfo) :
	fileParser(parser), cpParams(params), toolInfo(toolInfo), targetArchitecture(fileParser.getTargetArchitecture()),
	search(new Search(fileParser)), heuristics(nullptr), internalDatabase(nullptr)
{

}

/**
 * Destructor (default implementation)
 */
CompilerDetector::~CompilerDetector()
{
	delete heuristics;
	delete search;
}

/**
 * External databases parsing
 * @return @c true if at least one external database was detected, @c false otherwise
 */
bool CompilerDetector::getExternalDatabases()
{
	auto thisDir = FilesystemPath(".");
	auto result = false;

	// iterating over all files in directory
	for(const auto *subpath : thisDir)
	{
		if(subpath->isFile() && std::any_of(externalSuffixes.begin(), externalSuffixes.end(),
			[&] (const auto &suffix)
			{
				return endsWith(subpath->getPath(), suffix);
			}
		))
		{
			result = true;
			externalDatabase.push_back(subpath->getPath());
		}
	}

	return result;
}

/**
 * Remove every detected compiler wchich has less similarity than @a refRatio
 *
 * Compilers which have not been detected based on signatures are not affected
 * @param refRatio Similarity ratio
 */
void CompilerDetector::removeCompilersWithLessSimilarity(double refRatio)
{
	double actRatio;

	for(std::size_t i = 0, e = toolInfo.detectedTools.size(); i < e; ++i)
	{
		if(toolInfo.detectedTools[i].source == DetectionMethod::SIGNATURE)
		{
			actRatio = static_cast<double>(toolInfo.detectedTools[i].agreeCount) / toolInfo.detectedTools[i].impCount;
			if(actRatio + std::numeric_limits<double>::epsilon() * std::abs(actRatio) < refRatio)
			{
				toolInfo.detectedTools.erase(toolInfo.detectedTools.begin() + i);
				--i;
				--e;
			}
		}
	}
}

/**
 * Remove redundant compilers
 */
void CompilerDetector::removeUnusedCompilers()
{
	std::size_t noOfCompilers = toolInfo.detectedTools.size();
	std::size_t lastBeneficial = 0;
	auto removeFlag = false;

	for(std::size_t i = 0; i < noOfCompilers; ++i)
	{
		if(toolInfo.isReliableResult(i))
		{
			lastBeneficial = i;
			removeFlag = true;
		}
	}

	if(removeFlag)
	{
		for(std::size_t i = lastBeneficial + 1; i < noOfCompilers; ++i)
		{
			if(toolInfo.detectedTools[i].source < DetectionMethod::SIGNATURE)
			{
				toolInfo.detectedTools.erase(toolInfo.detectedTools.begin() + i);
				--i;
				--noOfCompilers;
			}
		}
	}

	for(std::size_t i = 0; i < noOfCompilers; ++i)
	{
		const auto &first = toolInfo.detectedTools[i];

		for(std::size_t j = i + 1; j < noOfCompilers; ++j)
		{
			const auto &second = toolInfo.detectedTools[j];
			if(first.name == second.name && (first.versionInfo == second.versionInfo || second.versionInfo.empty()) &&
				(first.additionalInfo == second.additionalInfo || second.additionalInfo.empty()))
			{
				toolInfo.detectedTools.erase(toolInfo.detectedTools.begin() + j);
				--j;
				--noOfCompilers;
			}
		}
	}
}

/**
 * Try detect used compiler (or packer) based on heuristics
 */
void CompilerDetector::getAllHeuristics()
{
	if (heuristics)
	{
		heuristics->getAllHeuristics();
	}
}

/**
 * Try detect used compiler (or packer) based on signatures
 * @return Status of detection (ReturnCode::OK if all is OK)
 */
ReturnCode CompilerDetector::getAllSignatures()
{
	YaraDetector yara;

	yara.addRules("import \"pe\"");
	yara.addRules("import \"elf\"");
	yara.addRules("import \"macho\"");

	if(cpParams.internal && internalDatabase)
	{
		for(const auto *rules : *internalDatabase)
		{
			yara.addRules(rules);
		}
	}
	if(cpParams.external && getExternalDatabases())
	{
		for(const auto &item : externalDatabase)
		{
			yara.addRuleFile(item);
		}
	}

	yara.analyze(fileParser.getPathToFile(), cpParams.searchType != SearchType::EXACT_MATCH);
	const auto &detected = yara.getDetectedRules();
	const auto &undetected = yara.getUndetectedRules();
	auto result = false;
	if(cpParams.searchType == SearchType::EXACT_MATCH || (cpParams.searchType == SearchType::MOST_SIMILAR && !detected.empty()))
	{
		for(const auto &rule : detected)
		{
			const auto *match = rule.getFirstMatch();
			const auto *nameMeta = rule.getMeta("name");
			const auto *patternMeta = rule.getMeta("pattern");
			if(!match || !nameMeta || !patternMeta)
			{
				continue;
			}
			const auto nibbles = search->countImpNibbles(patternMeta->getStringValue());
			if(nibbles)
			{
				result = true;
				const auto *toolMeta = rule.getMeta("tool");
				const auto *versionMeta = rule.getMeta("version");
				const auto *commentMeta = rule.getMeta("comment");
				const auto *languageMeta = rule.getMeta("language");
				const auto *bytecodeMeta = rule.getMeta("bytecode");
				commentMeta = commentMeta ? commentMeta : rule.getMeta("extra");
				toolInfo.addTool(nibbles, nibbles, toolMeta ? metaToTool(toolMeta->getStringValue()) : ToolType::UNKNOWN,
					nameMeta->getStringValue(), versionMeta ? versionMeta->getStringValue() : "", commentMeta ? commentMeta->getStringValue() : "");
				if (languageMeta)
				{
					toolInfo.addLanguage(languageMeta->getStringValue(), "", bytecodeMeta ? true : false);
				}
			}
		}

		return (result ? ReturnCode::OK : ReturnCode::UNKNOWN_CP);
	}

	Similarity sim;
	double maxRatio = 0.0;

	for(const auto &rules : {detected, undetected})
	{
		for(const auto &rule : rules)
		{
			const auto *nameMeta = rule.getMeta("name");
			auto *patternMeta = rule.getMeta("pattern");
			if(!nameMeta || !patternMeta)
			{
				continue;
			}
			auto pattern = patternMeta->getStringValue();
			while(endsWith(pattern,  ";"))
			{
				pattern.pop_back();
			}
			const auto *match = rule.getFirstMatch();
			const auto *toolMeta = rule.getMeta("tool");
			const auto *versionMeta = rule.getMeta("version");
			const auto *commentMeta = rule.getMeta("comment");
			commentMeta = commentMeta ? commentMeta : rule.getMeta("extra");
			if(match)
			{
				const auto nibbles = search->countImpNibbles(pattern);
				if(nibbles)
				{
					result = true;
					maxRatio = 1.0;
					toolInfo.addTool(nibbles, nibbles, toolMeta ? metaToTool(toolMeta->getStringValue()) : ToolType::UNKNOWN,
						nameMeta->getStringValue(), versionMeta ? versionMeta->getStringValue() : "", commentMeta ? commentMeta->getStringValue() : "");
				}
				continue;
			}

			std::size_t base = 0;
			const auto *absoluteStartMeta = rule.getMeta("absoluteStart");
			if(absoluteStartMeta)
			{
				if(!strToNum(absoluteStartMeta->getStringValue(), base))
				{
					continue;
				}
			}
			else if(toolInfo.entryPointOffset)
			{
				base = toolInfo.epOffset;
			}
			else
			{
				continue;
			}

			std::size_t startShift = 0, endShift = 0;
			const auto *startMeta = rule.getMeta("start");
			const auto *endMeta = rule.getMeta("end");
			if(startMeta)
			{
				startShift = startMeta->getIntValue();
			}
			if(endMeta)
			{
				endShift = endMeta->getIntValue();
			}
			const auto start = base + startShift;
			const auto end = base + endShift + fileParser.bytesFromNibblesRounded(pattern.length()) - 1;
			if(search->areaSimilarity(pattern, sim, start, end) && (cpParams.searchType == SearchType::SIM_LIST ||
				(cpParams.searchType == SearchType::MOST_SIMILAR && sim.ratio >= maxRatio)))
			{
				result = true;
				maxRatio = sim.ratio;
				toolInfo.addTool(sim.same, sim.total, toolMeta ? metaToTool(toolMeta->getStringValue()) : ToolType::UNKNOWN,
					nameMeta->getStringValue(), versionMeta ? versionMeta->getStringValue() : "", commentMeta ? commentMeta->getStringValue() : "");
			}
		}
	}

	if(cpParams.searchType == SearchType::MOST_SIMILAR)
	{
		removeCompilersWithLessSimilarity(maxRatio);
	}

	return (result ? ReturnCode::OK : ReturnCode::UNKNOWN_CP);
}

/**
 * Detects all compilers (and packers) based on signatures and heuristics
 * @return Status of detection (ReturnCode::OK if all is OK)
 */
ReturnCode CompilerDetector::getAllCompilers()
{
	const auto status = getAllSignatures();
	getAllHeuristics();
	std::sort(toolInfo.detectedTools.begin(), toolInfo.detectedTools.end(), compareForSort);
	removeUnusedCompilers();
	if(toolInfo.detectedLanguages.empty())
	{
		for(const auto &item : toolInfo.detectedTools)
		{
			if(!item.isReliable())
			{
				continue;
			}

			const auto name = toLower(item.name);
			if(contains(name, ".net"))
			{
				toolInfo.addLanguage("CIL/.NET", "", true);
			}
		}
	}

	const bool isSomethingDetected = toolInfo.detectedTools.size() || toolInfo.detectedLanguages.size();
	return (status == ReturnCode::UNKNOWN_CP && isSomethingDetected) ? ReturnCode::OK : status;
}

/**
 * Detect all supported information about used compiler or packer
 * @return Status of detection (ReturnCode::OK if all is OK)
 *
 * Compiler can be successfully detected even if is returned a value other than ReturnCode::OK
 */
ReturnCode CompilerDetector::getAllInformation()
{
	if(!fileParser.isInValidState())
	{
		return ReturnCode::FILE_PROBLEM;
	}

	fileParser.getImageBaseAddress(toolInfo.imageBase);
	toolInfo.entryPointAddress = fileParser.getEpAddress(toolInfo.epAddress);
	toolInfo.entryPointOffset = fileParser.getEpOffset(toolInfo.epOffset);
	const bool invalidEntryPoint = !toolInfo.entryPointAddress || !toolInfo.entryPointOffset;
	if(!fileParser.getHexEpBytes(toolInfo.epBytes, EP_BYTES_SIZE) && !invalidEntryPoint && !fileParser.isInValidState())
	{
		return ReturnCode::FILE_PROBLEM;
	}

	const auto *epSec = fileParser.getEpSection();
	toolInfo.entryPointSection = epSec;
	if(epSec)
	{
		toolInfo.epSection = Section(*epSec);
	}

	auto status = getAllCompilers();
	if(invalidEntryPoint)
	{
		if (fileParser.isExecutable() || toolInfo.entryPointAddress || toolInfo.entryPointSection)
		{
			status = ReturnCode::ENTRY_POINT_DETECTION;
		}
	}

	return status;
}

} // namespace cpdetect
