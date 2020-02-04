/**
 * @file include/retdec/yaracpp/yara_detector/yara_detector.h
 * @brief Interpret of YARA rules.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#pragma once

#include <string>
#include <unordered_map>
#include <vector>

#include <yara/compiler.h>
#include <yara/types.h>

#include "retdec/yaracpp/types/yara_rule.h"

namespace yaracpp
{

/**
 * Interpret of YARA rules
 */
class YaraDetector
{
	public:
		/**
		 * Structure for callback function
		 */
		class CallbackSettings
		{
			private:
				bool storeAll;                           ///< set to @c true if you want store all rules (not only detected)
				std::vector<YaraRule> &storedDetected;   ///< link to detected rules
				std::vector<YaraRule> &storedUndetected; ///< link to undetected rules
			public:
				CallbackSettings(bool cStoreAll, std::vector<YaraRule> &cDetected, std::vector<YaraRule> &cUndetected);
				~CallbackSettings();

				/// @name Other methods
				/// @{
				void addDetected(YaraRule &rule);
				void addUndetected(YaraRule &rule);
				bool storeAllRules() const;
				/// @}
		};

		struct RuleFile
		{
			RuleFile(const std::string& pathToFile_, bool precompiled_, FILE* handle_)
				: pathToFile(pathToFile_), precompiled(precompiled_), handle(handle_) {}

			std::string pathToFile;
			bool precompiled;
			FILE* handle;
		};

	private:
		YR_COMPILER *compiler;                   ///< compiler or text rules
		std::vector<FILE*> files;                ///< representation of files with rules
		std::vector<YaraRule> detectedRules;     ///< representation of detected rules
		std::vector<YaraRule> undetectedRules;   ///< representation of undetected rules
		YR_RULES* textFilesRules;                ///< rules from input text files
		std::vector<YR_RULES*> precompiledRules; ///< rules from precompiled files
		bool stateIsValid;                       ///< internal state of instance
		bool needsRecompilation;                 ///< indicates whether text files need recompilation

		/// @name Static auxiliary methods
		/// @{
		static int yaraCallback(int message, void *messageData, void *userData);
		/// @}

		/// @name Auxiliary detection methods
		/// @{
		template <typename T> bool analyzeWithScan(T&& value, bool storeAllRules = false);
		YR_RULES* getCompiledRules();
		/// @}
	public:
		YaraDetector();
		~YaraDetector();

		/// @name Other methods
		/// @{
		bool addRules(const char *string);
		bool addRuleFile(const std::string &pathToFile, const std::string &nameSpace = std::string());
		bool isInValidState() const;
		/// @}

		/// @name Detection methods
		/// @{
		bool analyze(const std::string &pathToInputFile, bool storeAllRules = false);
		bool analyze(std::vector<std::uint8_t> &bytes, bool storeAllRules = false);
		const std::vector<YaraRule>& getDetectedRules() const;
		const std::vector<YaraRule>& getUndetectedRules() const;
		/// @}
};

} // namespace yaracpp
