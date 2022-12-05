/**
 * @file src/fileinfo/fileinfo.cpp
 * @brief Main function and related things.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <regex>

#include <rapidjson/document.h>
#include <llvm/Support/ErrorHandling.h>

#include "retdec/utils/binary_path.h"
#include "retdec/utils/conversion.h"
#include "retdec/utils/memory.h"
#include "retdec/utils/io/log.h"
#include "retdec/utils/string.h"
#include "retdec/utils/time.h"
#include "retdec/utils/version.h"
#include "retdec/ar-extractor/detection.h"
#include "retdec/cpdetect/errors.h"
#include "retdec/cpdetect/settings.h"
#include "retdec/fileformat/utils/format_detection.h"
#include "retdec/fileformat/utils/other.h"
#include "retdec/serdes/std.h"
#include "fileinfo/file_detector/detector_factory.h"
#include "fileinfo/file_detector/macho_detector.h"
#include "fileinfo/file_presentation/config_presentation.h"
#include "fileinfo/file_presentation/json_presentation.h"
#include "fileinfo/file_presentation/plain_presentation.h"
#include "fileinfo/pattern_detector/pattern_detector.h"

using namespace retdec::utils;
using namespace retdec::utils::io;
using namespace retdec::ar_extractor;
using namespace retdec::cpdetect;
using namespace retdec::fileformat;
using namespace retdec::fileinfo;

namespace
{

/**
 * Program parameters
 */
struct ProgParams
{
	/// name of input file
	std::string filePath;
	/// type of search
	SearchType searchMode = SearchType::EXACT_MATCH;
	/// use of internal signature database
	bool internalDatabase = true;
	///< use of external signature database
	bool externalDatabase = false;
	///< print output as plain text
	bool plainText = true;
	///< print all detected information (except strings)
	bool verbose = false;
	///< print explanatory notes
	bool explanatory = false;
	///< flag for generating config file
	bool generateConfigFile = false;
	///< name of the config file
	std::string configFile;
	///< name of the file with the DLL list
	std::string dllListFile;
	///< paths to YARA malware rules
	std::set<std::string> yaraMalwarePaths;
	///< paths to YARA crypto rules
	std::set<std::string> yaraCryptoPaths;
	///< paths to YARA other rules
	std::set<std::string> yaraOtherPaths;
	std::size_t maxMemory = 0;
	/// limit maximal memory to half of system RAM
	bool maxMemoryHalfRAM = false;
	/// number of bytes to load from entry point
	std::size_t epBytesCount = EP_BYTES_SIZE;
	/// load flags for `fileformat`
	LoadFlags loadFlags = LoadFlags::NONE;
	/// flag whether to include analysis time into the output
	bool analysisTime = false;

	friend std::ostream& operator<<(std::ostream& os, const ProgParams& pp);
};

std::ostream& operator<<(std::ostream& os, const ProgParams& pp)
{
	os << "input file         : " << pp.filePath << "\n";
	os << "search mode        : " << pp.searchMode << "\n";
	os << "use internal db    : " << std::boolalpha << pp.internalDatabase << "\n";
	os << "use external db    : " << pp.externalDatabase << "\n";
	os << "plain output       : " << pp.plainText << "\n";
	os << "verbose            : " << pp.verbose << "\n";
	os << "explanatory        : " << pp.explanatory << "\n";
	os << "generate config    : " << pp.generateConfigFile << "\n";
	os << "config file        : " << pp.configFile << "\n";
	os << "dll list file      : " << pp.dllListFile << "\n";
	os << "maximal memory     : " << pp.maxMemory << "\n";
	os << "max half memory    : " << pp.maxMemoryHalfRAM << "\n";
	os << "ep bytes count     : " << pp.epBytesCount << "\n";
	os << "load flags         : " << pp.loadFlags << "\n";
	os << "analysis time      : " << pp.analysisTime << "\n";

	os << "yara malware rules : " << "\n";
	for (auto& r : pp.yaraMalwarePaths)
		os << "\t" << r << "\n";
	os << "yara crypto rules  : " << "\n";
	for (auto& r : pp.yaraCryptoPaths)
		os << "\t" << r << "\n";
	os << "yara other rules   : " << "\n";
	for (auto& r : pp.yaraOtherPaths)
		os << "\t" << r << "\n";

	return os;
}

/**
 * LLVM fatal error handler information
 */
struct ErrorHandlerInfo
{
	ProgParams* params;
	FileInformation* fileinfo;
};

/**
 * LLVM fatal error handler
 * @param user_data Data necessary for error handling
 * @param reason Unused
 * @param gen_crash_diag Unused
 */
void fatalErrorHandler(void *user_data, const std::string& /*reason*/, bool /*gen_crash_diag*/)
{
	ProgParams* params = static_cast<ErrorHandlerInfo*>(user_data)->params;
	FileInformation *fileinfo = static_cast<ErrorHandlerInfo*>(user_data)->fileinfo;

	fileinfo->setStatus(ReturnCode::FORMAT_PARSER_PROBLEM);

	if(params->plainText)
	{
		PlainPresentation(*fileinfo, params->verbose, params->explanatory, params->analysisTime).present();
	}
	else
	{
		JsonPresentation(*fileinfo, params->verbose, params->analysisTime).present();
	}

	exit(static_cast<int>(ReturnCode::FORMAT_PARSER_PROBLEM));
}

/**
 * Print help text on standard output
 */
void printHelp()
{
	Log::info() << "fileinfo - dumper of information about executable file\n\n"
				<< "For compiler detection, program looks in the input file for YARA patterns.\n"
				<< "According to them, it determines compiler or packer used for file creation.\n"
				<< "Supported file formats are: " + joinStrings(getSupportedFileFormats()) + ".\n\n"
				<< "Usage: fileinfo [options] file\n\n"
				<< "Options list:\n"
				<< "    --help, -h            Display this help.\n"
				<< "    --version             Display program's version.\n"
				<< "\n"
				<< "Options specifying type of YARA patterns matching for detection of used compiler\n"
				<< "or packer:\n"
				<< "  From this group, only one option can be used. If no option is used, program\n"
				<< "  works with option \"--exact\".\n"
				<< "    --exact, -x           Search for identical pattern.\n"
				<< "    --similarity, -s      Search for most similar pattern.\n"
				<< "    --sim-list, -l        Write list of similarities of all compilers and\n"
				<< "                          packers in database.\n"
				<< "\n"
				<< "Options specifying signatures database:\n"
				<< "  If no option from this group is used, program uses neither of them.\n"
				<< "    --no-internal, -n     Do not use internal signatures database.\n"
				<< "                          Internal database is otherwise used implicitly.\n"
				<< "    --external, -e        Use external signatures database (databases).\n"
				<< "                          As external databases use all files from actual\n"
				<< "                          directory with relevant extension (.yar or .yara).\n"
				<< "\n"
				<< "Options for specifying path to files and/or directories with other external\n"
				<< "YARA rules:\n"
				<< "  From this group, any option can be used repeatedly. If no option from this\n"
				<< "  group is used, program does not use any external database of YARA rules.\n"
				<< "    --malware=fileOrDir, -m=fileOrDir\n"
				<< "                          Path to rules for detection of malware.\n"
				<< "    --crypto=fileOrDir, -C=fileOrDir\n"
				<< "                          Path to rules for detection of cryptography constants\n"
				<< "                          and functions.\n"
				<< "    --other=fileOrDir, -o=fileOrDir\n"
				<< "                          Path to other YARA rules.\n"
				<< "\n"
				<< "Options for specifying output format:\n"
				<< "  From this group, only one option can be used. If no option is used, program\n"
				<< "  works with option \"--plain\".\n"
				<< "    --plain, -p           Print output as plain text.\n"
				<< "    --json, -j            Print output in JSON format.\n"
				<< "\n"
				<< "Options for specifying properties to load from the file:\n"
				<< "    --strings, -S         Load strings in the input file and print them.\n"
				<< "    --no-hashes[=all|file|verbose]\n"
				<< "                          Do not print and calculate hashes.\n"
				<< "                          Either all hashes or only file/verbose hashes.\n"
				<< "                          All assumed if no argument specified.\n"
				<< "    --ep-bytes=N          Number of bytes to load from entry point. (Default: " << EP_BYTES_SIZE << ")\n"
				<< "\n"
				<< "Other options for specifying output:\n"
				<< "    --verbose, -v         Print more information about input file.\n"
				<< "                          Without this parameter program print only\n"
				<< "                          basic information.\n"
				<< "    --explanatory, -X     Print explanatory notes (only in plain text output).\n"
				<< "    --analysis-time       Print also analysis time into output.\n"
				<< "\n"
				<< "Options for specifying configuration file:\n"
				<< "    --config=file, -c=file\n"
				<< "                          Set path and name of the config which will be (re)generated.\n"
				<< "    --fileinfo-config=file\n"
				<< "                          Specify fileinfo configuration file to use.\n"
				<< "                          Configuration file can be used instead of these command line options.\n"
				<< "\n"
				<< "Options for limiting maximal memory:\n"
				<< "    --max-memory=N\n"
				<< "                          Limit maximal memory to N bytes (0 means no limit).\n"
				<< "    --max-memory-half-ram\n"
				<< "                          Limit maximal memory to half of system RAM.\n"
				<< "\n"
				<< "Options for specifying list of available DLLs:\n"
				<< "    --dlls=filename\n"
				<< "                          Load the list of present DLLs from the file.\n";
}

std::string getParamOrDie(const std::vector<std::string> &argv, std::size_t &i)
{
	if (argv.size() > i+1)
	{
		return argv[++i];
	}
	else
	{
		Log::error() << getErrorMessage(ReturnCode::ARG) << "\n\n";
		printHelp();
		exit(static_cast<int>(ReturnCode::ARG));
	}
}

/**
 * @return If @a path is relative, return an absolute path created from parent
 *         path of @a config file and relative @a path.
 */
std::string fixRelativePath(const std::string& path, const std::string& config)
{
	if (config.empty())
		return path;

	if (fs::path(path).is_relative())
	{
		auto root = fs::canonical(config).parent_path();
		return (root / path).string();
	}
	else
	{
		return path;
	}
}

bool jsonGetPathArray(
		rapidjson::Document& root,
		const std::string& name,
		std::set<std::string>& val,
		const std::string& configPath = "")
{
	if (root.HasMember(name))
	{
		if (root[name].IsArray())
		{
			for (auto& v : root[name].GetArray())
			{
				if (v.IsString())
				{
					if (v.GetStringLength())
					{
						auto path = fixRelativePath(
								v.GetString(),
								configPath
						);
						if (fs::exists(path))
						{
							val.insert(path);
						}
					}
				}
				else
				{
					Log::error() << Log::Error << "JSON config: \"" << name
							<< "\" has bad value!\n";
					return false;
				}
			}
		}
		else
		{
			Log::error() << Log::Error << "JSON config: \"" << name
					<< "\" has bad value!\n";
			return false;
		}
	}
	return true;
}

/**
 * Config JSON string processing.
 * @param params Structure for storing information
 * @param json JSON string to process
 * @param configPath Path to JSON config file, used for fixing relative paths
 * @return @c true if processing was completed successfully, @c false otherwise
 */
bool doConfigString(
		ProgParams& params,
		const std::string& json,
		const std::string& configPath = "")
{
	rapidjson::Document root;
	rapidjson::ParseResult ok = root.Parse<rapidjson::kParseCommentsFlag>(json);
	if (!ok)
	{
		Log::error() << Log::Error << "Failed to parse fileinfo JSON configuration!\n";
		return false;
	}

	if (root.HasMember("outputFormat"))
	{
		auto val = root["outputFormat"].IsString()
				? root["outputFormat"].GetString() : std::string();
		if (val == "plain") params.plainText = true;
		else if (val == "json") params.plainText = false;
		else
		{
			Log::error() << Log::Error << "JSON config: \"outputFormat\" has bad value!\n";
			return false;
		}
	}

	if (root.HasMember("yaraMatchingType"))
	{
		auto val = root["yaraMatchingType"].IsString()
				? root["yaraMatchingType"].GetString() : std::string();
		if (val == "exact") params.searchMode = SearchType::EXACT_MATCH;
		else if (val == "similarity") params.searchMode = SearchType::MOST_SIMILAR;
		else if (val == "sim-list") params.searchMode = SearchType::SIM_LIST;
		else
		{
			Log::error() << Log::Error << "JSON config: \"yaraMatchingType\" has bad value!\n";
			return false;
		}
	}

	if (root.HasMember("noHashes"))
	{
		auto val = root["noHashes"].IsString()
				? root["noHashes"].GetString() : std::string();
		if (val == "default")
		{
			params.loadFlags = LoadFlags::NONE;
		}
		else if (val == "all")
		{
			params.loadFlags = static_cast<LoadFlags>(params.loadFlags
					| LoadFlags::NO_FILE_HASHES
					| LoadFlags::NO_VERBOSE_HASHES);
		}
		else if (val == "file")
		{
			params.loadFlags = static_cast<LoadFlags>(params.loadFlags
					| LoadFlags::NO_FILE_HASHES);
		}
		else if (val == "verbose")
		{
			params.loadFlags = static_cast<LoadFlags>(params.loadFlags
									| LoadFlags::NO_VERBOSE_HASHES);
		}
		else
		{
			Log::error() << Log::Error << "JSON config: \"noHashes\" has bad value!\n";
			return false;
		}
	}

	if (!jsonGetPathArray(root, "externalMalwareYaraRules", params.yaraMalwarePaths, configPath)) return false;
	if (!jsonGetPathArray(root, "externalCryptoYaraRules", params.yaraCryptoPaths, configPath)) return false;
	if (!jsonGetPathArray(root, "externalOtherYaraRules", params.yaraOtherPaths, configPath)) return false;

	params.internalDatabase = retdec::serdes::deserializeBool(root, "useInternalSignatureDb", params.internalDatabase);
	params.externalDatabase = retdec::serdes::deserializeBool(root, "useExternalSignatureDb", params.externalDatabase);
	params.verbose = retdec::serdes::deserializeBool(root, "verbose", params.verbose);
	params.explanatory = retdec::serdes::deserializeBool(root, "explanatory", params.explanatory);
	params.maxMemoryHalfRAM = retdec::serdes::deserializeBool(root, "maxMemoryHalf", params.maxMemoryHalfRAM);
	params.analysisTime = retdec::serdes::deserializeBool(root, "analysisTime", params.analysisTime);

	if (root.HasMember("loadStrings"))
	{
		if (root["loadStrings"].IsBool())
		{
			if (root["loadStrings"].GetBool())
				params.loadFlags = static_cast<LoadFlags>(params.loadFlags
					| LoadFlags::DETECT_STRINGS);
			else
				params.loadFlags = static_cast<LoadFlags>(params.loadFlags
					& (~LoadFlags::DETECT_STRINGS));
		}
		else
		{
			Log::error() << Log::Error << "JSON config: \"loadStrings\" has bad value!\n";
			return false;
		}
	}

	if (root.HasMember("dlls"))
	{
		if (root["dlls"].IsString())
		{
			if (root["dlls"].GetStringLength())
			{
				auto path = fixRelativePath(
						root["dlls"].GetString(),
						configPath
				);
				if (fs::exists(path))
				{
					params.dllListFile = path;
				}
			}
		}
		else
		{
			Log::error() << Log::Error << "JSON config: \"dlls\" has bad value!\n";
			return false;
		}
	}

	params.epBytesCount = retdec::serdes::deserializeUint64(root, "epBytes", params.epBytesCount);
	params.maxMemory = retdec::serdes::deserializeUint64(root, "maxMemory", params.maxMemory);

	return true;
}

/**
 * Config file processing.
 * @param params Structure for storing information
 * @param configPath Path to fileinfo config file to read.
 *                   Default path relative to fileinfo binary is used of not
 *                   specified.
 * @return @c true if processing was completed successfully, @c false otherwise
 */
bool doConfigFile(ProgParams& params, const std::string& configPath = "")
{
	fs::path cp;

	if (configPath.empty())
	{
		auto binpath = retdec::utils::getThisBinaryDirectoryPath();
		cp = fs::path(fs::canonical(binpath).parent_path());
		cp.append("share");
		cp.append("retdec");
		cp.append("fileinfo-config.json");

		if (!fs::exists(cp))
		{
			// If the default config is not found, we ignore it.
			return true;
		}
	}
	else
	{
		cp = fs::path(configPath);

		// If the specified config file is not found, we consider it an error.
		if (!fs::exists(cp))
		{
			return false;
		}
	}

	std::ifstream jsonFile(cp.string(), std::ios::in | std::ios::binary);
	if (!jsonFile)
	{
		return false;
	}
	std::string jsonContent;
	jsonFile.seekg(0, std::ios::end);
	jsonContent.resize(jsonFile.tellg());
	jsonFile.seekg(0, std::ios::beg);
	jsonFile.read(&jsonContent[0], jsonContent.size());
	jsonFile.close();

	return doConfigString(params, jsonContent, cp.string());
}

/**
 * Parameters processing
 * @param argc Number of parameters
 * @param _argv Vector of parameters
 * @param params Structure for storing information
 * @return @c true if processing was completed successfully, @c false otherwise
 */
bool doParams(int argc, char **_argv, ProgParams &params)
{
	if (argc < 2)
	{
		printHelp();
		exit(EXIT_SUCCESS);
	}
	else if (!_argv)
	{
		return false;
	}

	std::vector<std::string> argv;

	std::set<std::string> withArgs = {
			"malware", "m", "crypto", "C", "other", "o", "config",
			"fileinfo-config", "c", "no-hashes", "max-memory", "ep-bytes",
			"dlls"
	};
	for (int i = 1; i < argc; ++i)
	{
		std::string a = _argv[i];

		bool added = false;
		for (auto& o : withArgs)
		{
			std::string start = (o.size() == 1 ? "-" : "--") + o + "=";
			if (retdec::utils::startsWith(a, start))
			{
				argv.push_back(a.substr(0, start.size()-1));
				argv.push_back(a.substr(start.size()));
				added = true;
				break;
			}
		}
		if (added)
		{
			continue;
		}

		argv.push_back(a);
	}

	// In the first pass, we process possible configuration file, so that
	// options it contains can be overwritten by ordinary command line options.
	//
	for (std::size_t i = 0; i < argv.size(); ++i)
	{
		if (argv[i] == "--fileinfo-config")
		{
			if(!doConfigFile(params, getParamOrDie(argv, i)))
			{
				return false;
			}
		}
	}

	for (std::size_t i = 0; i < argv.size(); ++i)
	{
		std::string c = argv[i];

		if (c == "-h" || c == "--help")
		{
			printHelp();
			exit(EXIT_SUCCESS);
		}
		else if (c == "--version")
		{
			Log::info() << version::getVersionStringLong() << "\n";
			exit(EXIT_SUCCESS);
		}
		else if (c == "-x" || c == "--exact")
		{
			params.searchMode = SearchType::EXACT_MATCH;
		}
		else if (c == "-s" || c == "--similarity")
		{
			params.searchMode = SearchType::MOST_SIMILAR;
		}
		else if (c == "-l" || c == "--sim-list")
		{
			params.searchMode = SearchType::SIM_LIST;
		}
		else if (c == "-n" || c == "--no-internal")
		{
			params.internalDatabase = false;
		}
		else if (c == "-e" || c == "--external")
		{
			params.externalDatabase = true;
		}
		else if (c == "-p" || c == "--plain")
		{
			params.plainText = true;
		}
		else if (c == "-j" || c == "--json")
		{
			params.plainText = false;
		}
		else if (c == "-v" || c == "--verbose")
		{
			params.verbose = true;
		}
		else if (c == "-X" || c == "--explanatory")
		{
			params.explanatory = true;
		}
		else if (c == "--analysis-time")
		{
			params.analysisTime = true;
		}
		else if (c == "-S" || c == "--strings")
		{
			params.loadFlags = static_cast<LoadFlags>(params.loadFlags
					| LoadFlags::DETECT_STRINGS);
		}
		else if (c == "-m" || c == "--malware")
		{
			params.yaraMalwarePaths.insert(getParamOrDie(argv, i));
		}
		else if (c == "-C" || c == "--crypto")
		{
			params.yaraCryptoPaths.insert(getParamOrDie(argv, i));
		}
		else if (c == "-c" || c == "--config")
		{
			params.configFile = getParamOrDie(argv, i);
			params.generateConfigFile = !params.configFile.empty();
		}
		else if (c == "--fileinfo-config")
		{
			// Ignore - already processed in the first pass.
			getParamOrDie(argv, i);
		}
		else if (c == "-o" || c == "--other")
		{
			params.yaraOtherPaths.insert(getParamOrDie(argv, i));
		}
		else if (c == "--max-memory")
		{
			auto maxMemoryString = getParamOrDie(argv, i);
			auto conversionSucceeded = strToNum(maxMemoryString, params.maxMemory);
			if (!conversionSucceeded) {
				return false;
			}
		}
		else if (c == "--max-memory-half-ram")
		{
			params.maxMemoryHalfRAM = true;
		}
		else if (c == "--no-hashes")
		{
			std::string value;
			if (argv.size() > i+1)
			{
				value = argv[i+1];
			}

			if (value == "file")
			{
				params.loadFlags = static_cast<LoadFlags>(params.loadFlags
						| LoadFlags::NO_FILE_HASHES);
				++i;
			}
			else if (value == "verbose")
			{
				params.loadFlags = static_cast<LoadFlags>(params.loadFlags
										| LoadFlags::NO_VERBOSE_HASHES);
				++i;
			}
			else
			{
				params.loadFlags = static_cast<LoadFlags>(params.loadFlags
						| LoadFlags::NO_FILE_HASHES
						| LoadFlags::NO_VERBOSE_HASHES);

				if (value == "all")
				{
					++i;
				}
			}
		}
		else if (c == "--ep-bytes")
		{
			auto epBytesCountString = getParamOrDie(argv, i);
			if (!strToNum(epBytesCountString, params.epBytesCount))
				return false;
		}
		else if (c == "--dlls")
		{
			auto dllListFile = getParamOrDie(argv, i);

			params.dllListFile = dllListFile;
		}
		else if (params.filePath.empty())
		{
			params.filePath = argv[i];
		}
		else
		{
			return false;
		}
	}

	if(params.filePath.empty())
	{
		return false;
	}

	return true;
}

/**
* Limits the maximal memory of the tool based on the command-line parameters.
*/
void limitMaximalMemoryIfRequested(const ProgParams& params)
{
	// Ignore errors as there is no easy way of reporting them at this
	// point (in a way that would work both with --plain and --json).
	// We have at least regression tests for this.
	if(params.maxMemoryHalfRAM)
	{
		limitSystemMemoryToHalfOfTotalSystemMemory();
	}
	else if(params.maxMemory > 0)
	{
		limitSystemMemory(params.maxMemory);
	}
}

} // anonymous namespace

/**
 * Main function
 * @param argc Number of parameters
 * @param argv Vector of parameters
 * @return Program status
 */
int main(int argc, char* argv[])
{
	ProgParams params;
	if(!doConfigFile(params))
	{
		Log::error() << getErrorMessage(ReturnCode::ARG) << "\n\n";
		printHelp();
		return static_cast<int>(ReturnCode::ARG);
	}

	if(!doParams(argc, argv, params))
	{
		Log::error() << getErrorMessage(ReturnCode::ARG) << "\n\n";
		printHelp();
		return static_cast<int>(ReturnCode::ARG);
	}

	limitMaximalMemoryIfRequested(params);

	bool useConfig = true;
	retdec::config::Config config;
	if(params.generateConfigFile && !params.configFile.empty())
	{
		try
		{
			config.readJsonFile(params.configFile);
		}
		catch (const retdec::config::FileNotFoundException&)
		{
			useConfig = false;
		}
		catch (const retdec::config::ParseException&)
		{
			useConfig = false;
		}
	}

	DetectParams searchPar(params.searchMode, params.internalDatabase, params.externalDatabase, params.epBytesCount);
	const auto fileFormat = detectFileFormat(params.filePath, useConfig && config.fileFormat.isRaw());
	FileInformation fileinfo;
	FileDetector *fileDetector = nullptr;
	fileinfo.setPathToFile(params.filePath);
	fileinfo.setAnalysisTime(timestampToDate(getCurrentTimestamp()));
	fileinfo.setFileFormatEnum(fileFormat);
	ErrorHandlerInfo hInfo { &params, &fileinfo };
	llvm::install_fatal_error_handler(fatalErrorHandler, &hInfo);
	switch(fileFormat)
	{
		case Format::UNDETECTABLE:
		{
			fileinfo.setStatus(ReturnCode::FILE_NOT_EXIST);
			break;
		}
		default:
		{
			fileDetector = createFileDetector(params.filePath, params.dllListFile, fileFormat, fileinfo, searchPar, params.loadFlags);
			if(fileDetector)
			{
				if(!fileDetector->getFileParser()->isInValidState())
				{
					// Check if Mach-O is archive.
					if (fileFormat == Format::MACHO)
					{
						auto machoDetecor = static_cast<MachODetector*>(fileDetector);
						if (machoDetecor->isMachoUniversalArchive())
						{
							fileinfo.setStatus(ReturnCode::MACHO_AR_DETECTED);
							break;
						}
					}

					fileinfo.setStatus(ReturnCode::FORMAT_PARSER_PROBLEM);
					break;
				}

				if(useConfig)
				{
					fileDetector->setConfigFile(config);
				}
				fileDetector->getAllInformation();
			}
			else
			{
				if(isArchive(params.filePath))
				{
					fileinfo.setStatus(ReturnCode::ARCHIVE_DETECTED);
				}
				else
				{
					fileinfo.setStatus(ReturnCode::UNKNOWN_FORMAT);
				}
			}
			PatternDetector patternDetector(fileDetector ? fileDetector->getFileParser() : nullptr, fileinfo);
			patternDetector.addFilePaths("malware", params.yaraMalwarePaths);
			patternDetector.addFilePaths("crypto", params.yaraCryptoPaths);
			patternDetector.addFilePaths("other", params.yaraOtherPaths);
			patternDetector.analyze();
		}
	}

	// print results on standard output
	if(params.plainText)
	{
		PlainPresentation(fileinfo, params.verbose, params.explanatory, params.analysisTime).present();
	}
	else
	{
		JsonPresentation(fileinfo, params.verbose, params.analysisTime).present();
	}

	// generate configuration file
	auto res = fileinfo.getStatus();
	if(params.generateConfigFile)
	{
		auto config = ConfigPresentation(fileinfo, params.configFile);
		if(!config.present())
		{
			Log::error() << "Error: loading of config failed: " << config.getErrorMessage() << "\n";
			res = ReturnCode::FILE_PROBLEM;
		}
	}

	delete fileDetector;
	return isFatalError(res) ? static_cast<int>(res) : static_cast<int>(ReturnCode::OK);
}
