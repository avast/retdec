/**
 * @file include/retdec/yaracpp/yara_detector.h
 * @brief Interpret of YARA rules.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_YARACPP_YARA_DETECTOR_H
#define RETDEC_YARACPP_YARA_DETECTOR_H

#include <string>
#include <unordered_map>
#include <vector>

#include "retdec/yaracpp/yara_rule.h"

typedef struct _YR_COMPILER YR_COMPILER;
typedef struct YR_RULES YR_RULES;
typedef struct YR_SCAN_CONTEXT YR_SCAN_CONTEXT;

namespace retdec {
namespace yaracpp {

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
				/// set to @c true if you want store all rules (not only detected)
				bool storeAll;
				/// link to detected rules
				std::vector<YaraRule> &storedDetected;
				/// link to undetected rules
				std::vector<YaraRule> &storedUndetected;
			public:
				CallbackSettings(
						bool cStoreAll,
						std::vector<YaraRule> &cDetected,
						std::vector<YaraRule> &cUndetected
				);

				/// @name Other methods
				/// @{
				void addDetected(YaraRule &rule);
				void addUndetected(YaraRule &rule);
				bool storeAllRules() const;
				/// @}
		};

		struct RuleFile
		{
			RuleFile(
					const std::string& pathToFile_,
					bool precompiled_,
					FILE* handle_)
					: pathToFile(pathToFile_)
					, precompiled(precompiled_)
					, handle(handle_)
			{}

			std::string pathToFile;
			bool precompiled;
			FILE* handle;
		};

	private:
		/// compiler or text rules
		YR_COMPILER *compiler = nullptr;
		/// representation of files with rules
		std::vector<FILE*> files;
		/// representation of detected rules
		std::vector<YaraRule> detectedRules;
		/// representation of undetected rules
		std::vector<YaraRule> undetectedRules;
		/// rules from input text files
		YR_RULES* textFilesRules = nullptr;
		/// rules from precompiled files
		std::vector<YR_RULES*> precompiledRules;
		/// internal state of instance
		bool stateIsValid = true;
		/// indicates whether text files need recompilation
		bool needsRecompilation = true;

		/// @name Static auxiliary methods
		/// @{
		static int yaraCallback(
				YR_SCAN_CONTEXT* context,
				int message,
				void *messageData,
				void *userData
		);
		/// @}

		/// @name Auxiliary detection methods
		/// @{
		template <typename T> bool analyzeWithScan(
				T&& value,
				bool storeAllRules = false
		);
		YR_RULES* getCompiledRules();
		/// @}
	public:
		YaraDetector();
		~YaraDetector();

		/// @name Other methods
		/// @{
		bool addRules(const char *string);
		bool addRuleFile(
				const std::string &pathToFile,
				const std::string &nameSpace = std::string()
		);
		bool isInValidState() const;
		/// @}

		/// @name Detection methods
		/// @{
		bool analyze(
				const std::string &pathToInputFile,
				bool storeAllRules = false
		);
		bool analyze(
				std::vector<std::uint8_t> &bytes,
				bool storeAllRules = false
		);
		const std::vector<YaraRule>& getDetectedRules() const;
		const std::vector<YaraRule>& getUndetectedRules() const;
		/// @}
};

} // namespace yaracpp
} // namespace retdec

#endif
