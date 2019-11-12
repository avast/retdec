/**
 * @file src/config/config.cpp
 * @brief Decompilation configuration manipulation.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <fstream>

#include "retdec/config/config.h"
#include "retdec/serdes/address.h"
#include "retdec/serdes/architecture.h"
#include "retdec/serdes/class.h"
#include "retdec/serdes/file_format.h"
#include "retdec/serdes/file_type.h"
#include "retdec/serdes/function.h"
#include "retdec/serdes/language.h"
#include "retdec/serdes/object.h"
#include "retdec/serdes/pattern.h"
#include "retdec/serdes/vtable.h"
#include "retdec/serdes/tool_info.h"
#include "retdec/serdes/type.h"
#include "retdec/serdes/std.h"
#include "retdec/utils/string.h"
#include "retdec/utils/time.h"

using namespace Json;

namespace {

const std::string JSON_ida               = "ida";
const std::string JSON_date              = "date";
const std::string JSON_time              = "time";
const std::string JSON_inputFile         = "inputFile";
const std::string JSON_unpackedInputFile = "inputFileUnpacked";
const std::string JSON_pdbInputFile      = "inputFilePdb";
const std::string JSON_frontendVersion   = "frontendVersion";
const std::string JSON_parameters        = "decompParams";
const std::string JSON_architecture      = "architecture";
const std::string JSON_fileType          = "fileType";
const std::string JSON_fileFormat        = "fileFormat";
const std::string JSON_tools             = "tools";
const std::string JSON_imageBase         = "imageBase";
const std::string JSON_entryPoint        = "entryPoint";
const std::string JSON_mainAddress       = "mainAddress";
const std::string JSON_sectionVMA        = "sectionVMA";
const std::string JSON_functions         = "functions";
const std::string JSON_globals           = "globals";
const std::string JSON_registers         = "registers";
const std::string JSON_languages         = "languages";
const std::string JSON_structures        = "structures";
const std::string JSON_vtables           = "vtables";
const std::string JSON_classes           = "classes";
const std::string JSON_patterns          = "patterns";

} // anonymous namespace

namespace retdec {
namespace config {

Config Config::empty(const std::string& path)
{
	Config config;
	config._configFileName = path;
	return config;
}

Config Config::fromFile(const std::string& path)
{
	Config config;
	config.readJsonFile(path);
	return config;
}

Config Config::fromJsonString(const std::string& json)
{
	Config config;
	config.readJsonString(json);
	return config;
}

bool Config::isIda() const { return _ida; }

void Config::setInputFile(const std::string& n)          { _inputFile = n; }
void Config::setUnpackedInputFile(const std::string& n)  { _unpackedInputFile = n; }
void Config::setPdbInputFile(const std::string& n)       { _pdbInputFile = n; }
void Config::setFrontendVersion(const std::string& n)    { _frontendVersion = n; }
void Config::setEntryPoint(const retdec::common::Address& a)     { _entryPoint = a; }
void Config::setMainAddress(const retdec::common::Address& a)    { _mainAddress = a; }
void Config::setSectionVMA(const retdec::common::Address& a)     { _sectionVMA = a; }
void Config::setImageBase(const retdec::common::Address& a)      { _imageBase = a; }
void Config::setIsIda(bool b)                            { _ida = b; }

std::string Config::getInputFile() const          { return _inputFile; }
std::string Config::getUnpackedInputFile() const  { return _unpackedInputFile; }
std::string Config::getPdbInputFile() const       { return _pdbInputFile; }
std::string Config::getFrontendVersion() const    { return _frontendVersion; }
std::string Config::getConfigFileName() const     { return _configFileName; }
retdec::common::Address Config::getEntryPoint() const     { return _entryPoint; }
retdec::common::Address Config::getMainAddress() const    { return _mainAddress; }
retdec::common::Address Config::getSectionVMA() const     { return _sectionVMA; }
retdec::common::Address Config::getImageBase() const      { return _imageBase; }

/**
 * Reads JSON file into internal representation.
 * If file can not be opened, an instance of @c FileNotFoundException is thrown.
 * If file can not be parsed, an instance of @c ParseException is thrown.
 * @param input Path to input JSON file.
 */
void Config::readJsonFile(const std::string& input)
{
	// The reading of the input file is based on
	// http://insanecoding.blogspot.cz/2011/11/how-to-read-in-file-in-c.html
	std::ifstream jsonFile(input, std::ios::in | std::ios::binary);
	if (!jsonFile)
	{
		_configFileName.clear();
		std::string msg = "Input file \"" + input + "\" can not be opened.";
		throw FileNotFoundException(msg);
	}

	std::string jsonContent;
	jsonFile.seekg(0, std::ios::end);
	jsonContent.resize(jsonFile.tellg());
	jsonFile.seekg(0, std::ios::beg);
	jsonFile.read(&jsonContent[0], jsonContent.size());
	jsonFile.close();

	readJsonString(jsonContent);
	_configFileName = input;
}

/**
 * Generates JSON configuration file.
 * @return Path to generated JSON file.
 */
std::string Config::generateJsonFile() const
{
	std::string out;
	if (!_configFileName.empty())
		out = _configFileName;
	return generateJsonFile( out );
}

/**
 * Generates JSON configuration file.
 * @param outputFilePath Path to output JSON file. If not set, use 'inputName'.
 * @return Path to generated JSON file.
 */
std::string Config::generateJsonFile(const std::string& outputFilePath) const
{
	std::string jsonName = (outputFilePath.empty()) ? (getInputFile() + ".json") : (outputFilePath);

	std::ofstream jsonFile( jsonName.c_str() );
	jsonFile << generateJsonString();

	return jsonName;
}

/**
 * Generates string containing JSON representation of configuration.
 * @return JSON string.
 */
std::string Config::generateJsonString() const
{
	Json::Value root;

	root[JSON_date]           = retdec::utils::getCurrentDate();
	root[JSON_time]           = retdec::utils::getCurrentTime();
	root[JSON_inputFile]      = getInputFile();

	if (isIda()) root[JSON_ida] = isIda();
	if (!getUnpackedInputFile().empty()) root[JSON_unpackedInputFile] = getUnpackedInputFile();
	if (!getPdbInputFile().empty()) root[JSON_pdbInputFile] = getPdbInputFile();
	if (!getFrontendVersion().empty()) root[JSON_frontendVersion] = getFrontendVersion();
	if (getEntryPoint().isDefined()) root[JSON_entryPoint] = serdes::serialize(getEntryPoint());
	if (getMainAddress().isDefined()) root[JSON_mainAddress] = serdes::serialize(getMainAddress());
	if (getSectionVMA().isDefined()) root[JSON_sectionVMA] = serdes::serialize(getSectionVMA());
	if (getImageBase().isDefined()) root[JSON_imageBase] = serdes::serialize(getImageBase());

	root[JSON_parameters]     = parameters.getJsonValue();
	root[JSON_architecture]   = serdes::serialize(architecture);
	root[JSON_fileType]       = serdes::serialize(fileType);
	root[JSON_fileFormat]     = serdes::serialize(fileFormat);
	root[JSON_tools]          = serdes::serialize(tools);
	root[JSON_languages]      = serdes::serialize(languages);
	root[JSON_functions]      = serdes::serialize(functions);
	root[JSON_globals]        = serdes::serialize(globals);
	root[JSON_registers]      = serdes::serialize(registers);
	root[JSON_structures]     = serdes::serialize(structures);
	root[JSON_vtables]        = serdes::serialize(vtables);
	root[JSON_classes]        = serdes::serialize(classes);
	root[JSON_patterns]       = serdes::serialize(patterns);

	StreamWriterBuilder builder;
	return writeString(builder, root);
}

/**
 * Reads string containig JSON representation of configuration.
 * If file can not be parsed, an instance of @c ParseException is thrown.
 * @param json JSON string.
 */
void Config::readJsonString(const std::string& json)
{
	Json::Value root;
	std::string errs;

	std::istringstream input(json);
	Json::CharReaderBuilder rbuilder;
	bool success = Json::parseFromStream(rbuilder, input, &root, &errs);
	if (!success || root.isNull() || !root.isObject() )
	{
		std::string errMsg = "Failed to parse configuration";
		std::size_t line = 0;
		std::size_t column = 0;

		if (!errs.empty())
		{
			const auto posNL = errs.find('\n');
			const auto posLine = errs.find("Line");
			const auto posColumn = errs.find("Column");

			if (posNL != std::string::npos
					&& posLine != std::string::npos
					&& posColumn != std::string::npos)
			{
				// Get error postion from message
				line = std::stoul(errs.substr(posLine + 5));
				column = std::stoul(errs.substr(posColumn + 7));

				// Get error description from message
				auto message = errs.substr(posNL + 1);
				errMsg = retdec::utils::trim(message, " .\r\n");
			}
		}

		throw ParseException(errMsg, line, column);
	}

	*this = Config();

	try
	{
		setIsIda( safeGetBool(root, JSON_ida) );
		setInputFile( safeGetString(root, JSON_inputFile) );
		setUnpackedInputFile( safeGetString(root, JSON_unpackedInputFile) );
		setPdbInputFile( safeGetString(root, JSON_pdbInputFile) );
		setFrontendVersion( safeGetString(root, JSON_frontendVersion) );
		serdes::deserialize(root[JSON_entryPoint], _entryPoint);
		serdes::deserialize(root[JSON_mainAddress], _mainAddress);
		serdes::deserialize(root[JSON_sectionVMA], _sectionVMA);
		serdes::deserialize(root[JSON_imageBase], _imageBase);

		parameters.readJsonValue( root[JSON_parameters] );
		serdes::deserialize(root[JSON_architecture], architecture);
		serdes::deserialize(root[JSON_fileType], fileType);
		serdes::deserialize(root[JSON_fileFormat], fileFormat);
		serdes::deserialize(root[JSON_tools], tools);
		serdes::deserialize(root[JSON_languages], languages);
		serdes::deserialize(root[JSON_functions], functions);
		serdes::deserialize(root[JSON_globals], globals);
		serdes::deserialize(root[JSON_registers], registers);
		serdes::deserialize(root[JSON_structures], structures);
		serdes::deserialize(root[JSON_vtables], vtables);
		serdes::deserialize(root[JSON_classes], classes);
		serdes::deserialize(root[JSON_patterns], patterns);
	}
	catch (const InternalException& e)
	{
		auto loc = retdec::utils::getLineAndColumnFromPosition(json, e.getPosition());
		throw ParseException(e.getMessage(), loc.first, loc.second);
	}
}

} // namespace config
} // namespace retdec
