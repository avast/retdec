/**
 * @file src/config/parameters.cpp
 * @brief Decompilation configuration manipulation: decompilation parameters.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/config/parameters.h"

namespace {

const std::string JSON_verboseOut               = "verboseOut";
const std::string JSON_keepAllFuncs             = "keepAllFuncs";
const std::string JSON_selectedDecodeOnly       = "selectedDecodeOnly";
const std::string JSON_outputFile               = "outputFile";
const std::string JSON_frontendOutputFile       = "frontEndOutputFile";
const std::string JSON_ordinalNumDir            = "ordinalNumDirectory";
const std::string JSON_userStaticSigPaths       = "userStaticSignPaths";
const std::string JSON_staticSigPaths           = "staticSignPaths";
const std::string JSON_libraryTypeInfoPaths     = "libraryTypeInfoPaths";
const std::string JSON_abiPaths                 = "abiPaths";
const std::string JSON_selectedFunctions        = "selectedFunctions";
const std::string JSON_frontendFunctions        = "frontendFunctions";
const std::string JSON_selectedNotFoundFncs     = "selectedNotFoundFncs";
const std::string JSON_selectedRanges           = "selectedRanges";
const std::string JSON_selectedInteresting      = "selectedInteresting";

} // anonymous namespace

namespace retdec {
namespace config {

/**
 * @return Decompilation will verbosely inform about the decompilation process.
 */
bool Parameters::isVerboseOutput() const
{
	return _verboseOutput;
}

/**
 * @return Keep all functions in the decompiler's output.
 * Otherwise, only functions reachable from main are kept.
 */
bool Parameters::isKeepAllFunctions() const
{
	return _keepAllFunctions;
}

/**
 * @return Decode only parts selected through selective decompilation.
 * Otherwise, entire binary is decoded.
 * This speeds up decompilation, but usually produces lower-quality results.
 */
bool Parameters::isSelectedDecodeOnly() const { return _selectedDecodeOnly; }

/**
 * Find out if some functions or ranges were selected in selective decompilation.
 * @return @c True if @c selectedFunctions or @c selectedRanges not empty,
 *         @c false otherwise.
 */
bool Parameters::isSomethingSelected() const
{
	return ( !selectedFunctions.empty() || !selectedRanges.empty());
}

/**
 * Find out if the provided function name is among helper frontend function names.
 * @param funcName Function name to check.
 * @return @c True if any frontend function is substring in @a funcName.
 *         @c False otherwise.
 */
bool Parameters::isFrontendFunction(const std::string& funcName) const
{
	for (auto& n : frontendFunctions)
	{
		if (funcName.find(n) != std::string::npos)
			return true;
	}
	return false;
}

void Parameters::setIsVerboseOutput(bool b)
{
	_verboseOutput = b;
}

void Parameters::setIsKeepAllFunctions(bool b)
{
	_keepAllFunctions = b;
}
void Parameters::setIsSelectedDecodeOnly(bool b)
{
	_selectedDecodeOnly = b;
}

void Parameters::setOutputFile(const std::string& n)
{
	_outputFile = n;
}

void Parameters::setFrontendOutputFile(const std::string& n)
{
	_frontendOutputFile = n;
}

void Parameters::setOrdinalNumbersDirectory(const std::string& n)
{
	_ordinalNumbersDirectory = n;
}

std::string Parameters::getOutputFile() const
{
	return _outputFile;
}

std::string Parameters::getFrontendOutputFile() const
{
	return _frontendOutputFile;
}

std::string Parameters::getOrdinalNumbersDirectory() const
{
	return _ordinalNumbersDirectory;
}

/**
 * Returns JSON object (associative array) holding parameters information.
 * @return JSON object.
 */
Json::Value Parameters::getJsonValue() const
{
	Json::Value params;

	params[JSON_verboseOut]         = isVerboseOutput();
	params[JSON_keepAllFuncs]       = isKeepAllFunctions();
	params[JSON_selectedDecodeOnly] = isSelectedDecodeOnly();
	params[JSON_outputFile]         = getOutputFile();
	params[JSON_frontendOutputFile] = getFrontendOutputFile();

	if (!getOrdinalNumbersDirectory().empty()) params[JSON_ordinalNumDir] = getOrdinalNumbersDirectory();

	params[JSON_selectedRanges]       = selectedRanges.getJsonValue();

	params[JSON_userStaticSigPaths]       = getJsonStringValueVisit(userStaticSignaturePaths);
	params[JSON_staticSigPaths]           = getJsonStringValueVisit(staticSignaturePaths);
	params[JSON_libraryTypeInfoPaths]     = getJsonStringValueVisit(libraryTypeInfoPaths);
	params[JSON_abiPaths]                 = getJsonStringValueVisit(abiPaths);
	params[JSON_selectedFunctions]        = getJsonStringValueVisit(selectedFunctions);
	params[JSON_frontendFunctions]        = getJsonStringValueVisit(frontendFunctions);
	params[JSON_selectedNotFoundFncs]     = getJsonStringValueVisit(selectedNotFoundFunctions);

	return params;
}

/**
 * Reads JSON object (associative array) holding parameters information.
 * @param val JSON object.
 */
void Parameters::readJsonValue(const Json::Value& val)
{
	if ( val.isNull() || !val.isObject() )
	{
		return;
	}

	setIsVerboseOutput( safeGetBool(val, JSON_verboseOut, false) );
	setIsKeepAllFunctions( safeGetBool(val, JSON_keepAllFuncs) );
	setIsSelectedDecodeOnly( safeGetBool(val, JSON_selectedDecodeOnly) );
	setOrdinalNumbersDirectory( safeGetString(val, JSON_ordinalNumDir) );
	setOutputFile( safeGetString(val, JSON_outputFile) );
	setFrontendOutputFile( safeGetString(val, JSON_frontendOutputFile) );

	selectedRanges.readJsonValue( val[JSON_selectedRanges] );

	readJsonStringValueVisit(staticSignaturePaths, val[JSON_staticSigPaths]);
	readJsonStringValueVisit(userStaticSignaturePaths, val[JSON_userStaticSigPaths]);
	readJsonStringValueVisit(libraryTypeInfoPaths, val[JSON_libraryTypeInfoPaths]);
	readJsonStringValueVisit(abiPaths, val[JSON_abiPaths]);
	readJsonStringValueVisit(selectedFunctions, val[JSON_selectedFunctions]);
	readJsonStringValueVisit(frontendFunctions, val[JSON_frontendFunctions]);
	readJsonStringValueVisit(selectedNotFoundFunctions, val[JSON_selectedNotFoundFncs]);
}

} // namespace config
} // namespace retdec
