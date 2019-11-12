/**
 * @file src/config/parameters.cpp
 * @brief Decompilation configuration manipulation: decompilation parameters.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/config/base.h"
#include "retdec/config/parameters.h"
#include "retdec/serdes/std.h"

namespace {

const std::string JSON_verboseOut               = "verboseOut";
const std::string JSON_keepAllFuncs             = "keepAllFuncs";
const std::string JSON_selectedDecodeOnly       = "selectedDecodeOnly";
const std::string JSON_outputFile               = "outputFile";
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

void Parameters::setOrdinalNumbersDirectory(const std::string& n)
{
	_ordinalNumbersDirectory = n;
}

std::string Parameters::getOutputFile() const
{
	return _outputFile;
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

	if (!getOrdinalNumbersDirectory().empty()) params[JSON_ordinalNumDir] = getOrdinalNumbersDirectory();

	params[JSON_selectedRanges]       = serdes::serialize(selectedRanges);

	params[JSON_userStaticSigPaths]       = serdes::serialize(userStaticSignaturePaths);
	params[JSON_staticSigPaths]           = serdes::serialize(staticSignaturePaths);
	params[JSON_libraryTypeInfoPaths]     = serdes::serialize(libraryTypeInfoPaths);
	params[JSON_abiPaths]                 = serdes::serialize(abiPaths);
	params[JSON_selectedFunctions]        = serdes::serialize(selectedFunctions);
	params[JSON_frontendFunctions]        = serdes::serialize(frontendFunctions);
	params[JSON_selectedNotFoundFncs]     = serdes::serialize(selectedNotFoundFunctions);

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

	serdes::deserialize(val[JSON_selectedRanges], selectedRanges);

	serdes::deserialize(val[JSON_staticSigPaths], staticSignaturePaths);
	serdes::deserialize(val[JSON_userStaticSigPaths], userStaticSignaturePaths);
	serdes::deserialize(val[JSON_libraryTypeInfoPaths], libraryTypeInfoPaths);
	serdes::deserialize(val[JSON_abiPaths], abiPaths);
	serdes::deserialize(val[JSON_selectedFunctions], selectedFunctions);
	serdes::deserialize(val[JSON_frontendFunctions], frontendFunctions);
	serdes::deserialize(val[JSON_selectedNotFoundFncs], selectedNotFoundFunctions);
}

} // namespace config
} // namespace retdec
