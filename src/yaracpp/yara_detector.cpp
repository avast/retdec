/**
 * @file src/yaracpp/yara_detector.cpp
 * @brief Interpret of YARA rules.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <yara.h>
#include <yara/compiler.h>
#include <yara/types.h>

#include "retdec/yaracpp/yara_detector.h"

namespace retdec {
namespace yaracpp {

namespace {

/**
 * Interface for YARA scanning interface. Uses template specialization
 * to decide whether to scan file or memory buffer.
 */
template <typename T>
struct Scanner {};

/**
 * Specialization for scanning files.
 */
template <>
struct Scanner<std::string>
{
	static bool scan(
			YR_RULES* rules,
			YR_CALLBACK_FUNC callback,
			YaraDetector::CallbackSettings& settings,
			const std::string& pathToFile)
	{
		return yr_rules_scan_file(
				rules,
				pathToFile.c_str(),
				0,
				callback,
				&settings, 0
		) == ERROR_SUCCESS;
	}
};

/**
 * Specialization for scanning memory buffers.
 */
template <>
struct Scanner<std::vector<std::uint8_t>>
{
	static bool scan(
			YR_RULES* rules,
			YR_CALLBACK_FUNC callback,
			YaraDetector::CallbackSettings& settings,
			const std::vector<std::uint8_t>& buffer)
	{
		return yr_rules_scan_mem(
				rules,
				const_cast<uint8_t*>(buffer.data()),
				buffer.size(),
				0,
				callback,
				&settings, 0
		) == ERROR_SUCCESS;
	}
};

/**
 * Interface for Scanner. Provides template type deduction and
 * always passes correct type into Scanner template.
 */
template <typename T>
bool scan(
		YR_RULES* rules,
		YR_CALLBACK_FUNC callback,
		YaraDetector::CallbackSettings& settings,
		T&& value)
{
	return Scanner<std::decay_t<T>>::scan(
			rules,
			callback,
			settings,
			std::forward<T>(value)
	);
}

} // anonymous namespace

/**
 * Constructor
 */
YaraDetector::YaraDetector()
{
	stateIsValid = ((yr_initialize() == ERROR_SUCCESS)
			&& (yr_compiler_create(&compiler) == ERROR_SUCCESS));
	std::uint32_t max_match_data = 65536;
	yr_set_configuration(YR_CONFIG_MAX_MATCH_DATA, &max_match_data);
}

/**
 * Destructor
 */
YaraDetector::~YaraDetector()
{
	for (auto* file : files)
	{
		if (file)
			fclose(file);
	}

	files.clear();
	detectedRules.clear();
	undetectedRules.clear();

	if (compiler)
	{
		yr_compiler_destroy(compiler);
	}

	if (textFilesRules)
		yr_rules_destroy(textFilesRules);

	for (auto* rules : precompiledRules)
	{
		if (rules)
			yr_rules_destroy(rules);
	}

	yr_finalize();
}

/**
 * Constructor of settings class
 * @param cStoreAll If this parameter is set to @c true, all rules will be
 *    stored (not only detected rules)
 * @param cDetected Into this variable detected rules will be stored
 * @param cUndetected Into this variable undetected rules will be stored
 */
YaraDetector::CallbackSettings::CallbackSettings(
		bool cStoreAll,
		std::vector<YaraRule> &cDetected,
		std::vector<YaraRule> &cUndetected)
		: storeAll(cStoreAll)
		, storedDetected(cDetected)
		, storedUndetected(cUndetected)
{

}

/**
 * Add detected rule
 * @param rule Rule to store
 */
void YaraDetector::CallbackSettings::addDetected(YaraRule &rule)
{
	storedDetected.push_back(rule);
}

/**
 * Add undetected rule
 * @param rule Rule to store
 */
void YaraDetector::CallbackSettings::addUndetected(YaraRule &rule)
{
	storedUndetected.push_back(rule);
}

/**
 * Check if storing of all rules (not only detected) is set
 * @return @c true if storing of all rules is set
 */
bool YaraDetector::CallbackSettings::storeAllRules() const
{
	return storeAll;
}

/**
 * Callback function for scanning of input file
 * @param context YARA context
 * @param message Type of message from libyara
 * @param messageData Content of message
 * @param userData @c Pointer for save information about detected rules
 * @return Instruction for the next scan
 *
 * Read libyara documentation for more detailed information about
 * callback function
 */
int YaraDetector::yaraCallback(
		YR_SCAN_CONTEXT* context,
		int message,
		void *messageData,
		void *userData)
{
	if(message == CALLBACK_MSG_IMPORT_MODULE
			|| message == CALLBACK_MSG_MODULE_IMPORTED)
	{
		return CALLBACK_CONTINUE;
	}
	else if(message == CALLBACK_MSG_SCAN_FINISHED)
	{
		return CALLBACK_ABORT;
	}
	else if(message != CALLBACK_MSG_RULE_MATCHING
			&& message != CALLBACK_MSG_RULE_NOT_MATCHING)
	{
		return CALLBACK_ERROR;
	}

	auto *settings = static_cast<CallbackSettings*>(userData);
	if(!settings)
	{
		return CALLBACK_ERROR;
	}
	else if(!settings->storeAllRules() && message == CALLBACK_MSG_RULE_NOT_MATCHING)
	{
		return CALLBACK_CONTINUE;
	}

	auto *actRule = static_cast<YR_RULE*>(messageData);
	if(!actRule)
	{
		return CALLBACK_ERROR;
	}

	YaraRule actual;
	actual.setName(actRule->identifier);
	YR_META *meta;
	yr_rule_metas_foreach(actRule, meta)
	{
		if(meta)
		{
			YaraMeta yaralMeta;
			yaralMeta.setId(meta->identifier);
			if(meta->type == META_TYPE_STRING)
			{
				yaralMeta.setType(YaraMeta::Type::String);
				yaralMeta.setStringValue(meta->string);
			}
			else
			{
				yaralMeta.setType(YaraMeta::Type::Int);
				yaralMeta.setIntValue(meta->integer);
			}
			actual.addMeta(yaralMeta);
		}
	}

	if(message == CALLBACK_MSG_RULE_MATCHING)
	{
		YR_STRING *string;
		yr_rule_strings_foreach(actRule, string)
		{
			if(string)
			{
				YR_MATCH *match;
				yr_string_matches_foreach(context, string, match)
				{
					if(match)
					{
						YaraMatch yaralMatch;
						yaralMatch.setOffset(match->base + match->offset);
						yaralMatch.setData(match->data, match->data_length);
						actual.addMatch(yaralMatch);
					}
				}
			}
		}
		settings->addDetected(actual);
	}
	else
	{
		settings->addUndetected(actual);
	}

	return CALLBACK_CONTINUE;
}

/**
 * Add text rules to compiler
 * @param string YARA rules to add
 */
bool YaraDetector::addRules(const char *string)
{
	const auto result = yr_compiler_add_string(compiler, string, nullptr);

	needsRecompilation = (result == 0);
	return needsRecompilation;
}

/**
 * Add external file with text rules
 * @param pathToFile Path to rule file
 * @param nameSpace Namespace to use for the given rule file. If the file is
 *                  already compiled, this has no effect. If it is a text file,
 *                  this allows to have multiple rules with the same ID across
 *                  multiple rule files.
 */
bool YaraDetector::addRuleFile(
		const std::string &pathToFile,
		const std::string &nameSpace)
{
	// AT first, try to load the files as precompiled file
	YR_RULES* rules = nullptr;
	if (yr_rules_load(pathToFile.c_str(), &rules) == ERROR_SUCCESS)
	{
		precompiledRules.push_back(rules);
	}
	// If we didn't succeeded consider it as text file
	else
	{
		auto file = fopen(pathToFile.c_str(), "r");
		if (!file)
			return false;

		const char* ns = nameSpace.empty() ? nullptr : nameSpace.c_str();
		if (yr_compiler_add_file(compiler, file, ns, nullptr) != 0)
		{
			fclose(file);
			return false;
		}

		files.push_back(file);
		needsRecompilation = true;
	}

	return true;
}

/**
 * Getter for state of instance
 * @return @c true if all is OK, @c false otherwise
 */
bool YaraDetector::isInValidState() const
{
	return stateIsValid;
}

/**
 * Analyze input file
 * @param pathToInputFile Path to input file
 * @param storeAllRules If this parameter is set to @c true,
 *                      store all rules (not only detected)
 * @return @c true if analysis completed without any error, otherwise @c false.
 */
bool YaraDetector::analyze(
		const std::string &pathToInputFile,
		bool storeAllRules)
{
	return analyzeWithScan(pathToInputFile, storeAllRules);
}

/**
 * Analyze input bytes
 * @param bytes Vector of input bytes
 * @param storeAllRules If this parameter is set to @c true,
 *                      store all rules (not only detected)
 * @return @c true if analysis completed without any error, otherwise @c false.
 */
bool YaraDetector::analyze(std::vector<std::uint8_t> &bytes, bool storeAllRules)
{
	return analyzeWithScan(bytes, storeAllRules);
}

/**
 * Get detected rules
 * @return Detected rules
 */
const std::vector<YaraRule>& YaraDetector::getDetectedRules() const
{
	return detectedRules;
}

/**
 * Get undetected rules
 * @return Undetected rules
 */
const std::vector<YaraRule>& YaraDetector::getUndetectedRules() const
{
	return undetectedRules;
}

/**
 * Analyze input sequence
 * @param value Value to analyze
 * @param storeAllRules If this parameter is set to @c true,
 *                      store all rules (not only detected)
 * @return @c true if analysis completed without any error, otherwise @c false.
 */
template <typename T>
bool YaraDetector::analyzeWithScan(T&& value, bool storeAllRules)
{
	auto settings = CallbackSettings(
			storeAllRules,
			detectedRules,
			undetectedRules
	);

	auto rules = getCompiledRules();
	if (!(rules))
		return false;

	if (!scan(rules, yaraCallback, settings, std::forward<T>(value)))
		return false;

	for (auto* rules : precompiledRules)
	{
		if (!scan(rules, yaraCallback, settings, std::forward<T>(value)))
			return false;
	}

	return true;
}

/**
 * Returns the compiled rules from text files.
 * @return Compiled rules.
 */
YR_RULES* YaraDetector::getCompiledRules()
{
	// File is text file and needs to be compiled first
	// All text files are compiled into single YR_RULES structure and
	// we shouldn't compile it twice if it's not needed
	// analyze() called for the first time or the file was added since the
	// last analyze() call
	if (needsRecompilation)
	{
		YR_RULES* rules = nullptr;
		if (yr_compiler_get_rules(compiler, &rules) != ERROR_SUCCESS)
			return nullptr;

		if (textFilesRules)
			yr_rules_destroy(textFilesRules);

		textFilesRules = rules;
		needsRecompilation = false;
	}

	return textFilesRules;
}

} // namespace yaracpp
} // namespace retdec
