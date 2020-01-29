/**
 * @file src/config/parameters.cpp
 * @brief Decompilation configuration manipulation: decompilation parameters.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>

#include "retdec/config/parameters.h"
#include "retdec/serdes/address.h"
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
template <typename Writer>
void Parameters::serialize(Writer& writer) const
{
	writer.StartObject();

	serdes::serializeBool(writer, JSON_verboseOut, isVerboseOutput());
	serdes::serializeBool(writer, JSON_keepAllFuncs, isKeepAllFunctions());
	serdes::serializeBool(writer, JSON_selectedDecodeOnly, isSelectedDecodeOnly());
	serdes::serializeString(writer, JSON_outputFile, getOutputFile());
	serdes::serializeString(writer, JSON_ordinalNumDir, getOrdinalNumbersDirectory());

	serdes::serializeContainer(writer, JSON_selectedRanges, selectedRanges);
	serdes::serializeContainer(writer, JSON_userStaticSigPaths, userStaticSignaturePaths);
	serdes::serializeContainer(writer, JSON_staticSigPaths, staticSignaturePaths);
	serdes::serializeContainer(writer, JSON_libraryTypeInfoPaths, libraryTypeInfoPaths);
	serdes::serializeContainer(writer, JSON_abiPaths, abiPaths);
	serdes::serializeContainer(writer, JSON_selectedFunctions, selectedFunctions);
	serdes::serializeContainer(writer, JSON_frontendFunctions, frontendFunctions);
	serdes::serializeContainer(writer, JSON_selectedNotFoundFncs, selectedNotFoundFunctions);

	writer.EndObject();
}
template void Parameters::serialize(
	rapidjson::PrettyWriter<rapidjson::StringBuffer>&) const;
template void Parameters::serialize(
	rapidjson::PrettyWriter<rapidjson::StringBuffer, rapidjson::ASCII<>>&) const;

/**
 * Reads JSON object (associative array) holding parameters information.
 * @param val JSON object.
 */
void Parameters::deserialize(const rapidjson::Value& val)
{
	if ( val.IsNull() || !val.IsObject() )
	{
		return;
	}

	setIsVerboseOutput( serdes::deserializeBool(val, JSON_verboseOut, false) );
	setIsKeepAllFunctions( serdes::deserializeBool(val, JSON_keepAllFuncs) );
	setIsSelectedDecodeOnly( serdes::deserializeBool(val, JSON_selectedDecodeOnly) );
	setOrdinalNumbersDirectory( serdes::deserializeString(val, JSON_ordinalNumDir) );
	setOutputFile( serdes::deserializeString(val, JSON_outputFile) );

	serdes::deserializeContainer(val, JSON_selectedRanges, selectedRanges);
	serdes::deserializeContainer(val, JSON_staticSigPaths, staticSignaturePaths);
	serdes::deserializeContainer(val, JSON_userStaticSigPaths, userStaticSignaturePaths);
	serdes::deserializeContainer(val, JSON_libraryTypeInfoPaths, libraryTypeInfoPaths);
	serdes::deserializeContainer(val, JSON_abiPaths, abiPaths);
	serdes::deserializeContainer(val, JSON_selectedFunctions, selectedFunctions);
	serdes::deserializeContainer(val, JSON_frontendFunctions, frontendFunctions);
	serdes::deserializeContainer(val, JSON_selectedNotFoundFncs, selectedNotFoundFunctions);
}

} // namespace config
} // namespace retdec
