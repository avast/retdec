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
#include "retdec/utils/filesystem_path.h"

namespace {

const std::string JSON_verboseOut               = "verboseOut";
const std::string JSON_keepAllFuncs             = "keepAllFuncs";
const std::string JSON_selectedDecodeOnly       = "selectedDecodeOnly";
const std::string JSON_ordinalNumDir            = "ordinalNumDirectory";
const std::string JSON_userStaticSigPaths       = "userStaticSignPaths";
const std::string JSON_staticSigPaths           = "staticSignPaths";
const std::string JSON_libraryTypeInfoPaths     = "libraryTypeInfoPaths";
const std::string JSON_cryptoPatternPaths       = "cryptoPatternPaths";
const std::string JSON_abiPaths                 = "abiPaths";
const std::string JSON_selectedFunctions        = "selectedFunctions";
const std::string JSON_selectedNotFoundFncs     = "selectedNotFoundFncs";
const std::string JSON_selectedRanges           = "selectedRanges";
const std::string JSON_llvmPasses               = "llvmPasses";
const std::string JSON_entryPoint               = "entryPoint";
const std::string JSON_mainAddress              = "mainAddress";
const std::string JSON_sectionVMA               = "sectionVMA";

const std::string JSON_inputFile                = "inputFile";
const std::string JSON_inputPdbFile             = "inputPdbFile";
const std::string JSON_outputFile               = "outputFile";
const std::string JSON_outputBitcodeFile        = "outputBitcodeFile";
const std::string JSON_outputAsmFile            = "outputAsmFile";
const std::string JSON_outputLlFile             = "outputLlFile";
const std::string JSON_outputConfigFile         = "outputConfigFile";
const std::string JSON_outputUnpackedFile       = "outputUnpackedFile";

const std::string JSON_backendDisabledOpts      = "backendDisabledOpts";
const std::string JSON_backendNoOpts            = "backendNoOpts";
const std::string JSON_detectStaticCode         = "detectStaticCode";

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

bool Parameters::isMaxMemoryLimitHalfRam() const
{
	return _maxMemoryLimitHalfRam;
}

bool Parameters::isBackendNoOpts() const
{
	return _backendNoOpts;
}

bool Parameters::isDetectStaticCode() const
{
	return _detectStaticCode;
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

void Parameters::setOutputBitcodeFile(const std::string& file)
{
	_outputBitcodeFile = file;
}

void Parameters::setOutputAsmFile(const std::string& file)
{
	_outputAsmFile = file;
}

void Parameters::setOutputLlvmirFile(const std::string& file)
{
	_outputLlFile = file;
}

void Parameters::setOutputConfigFile(const std::string& file)
{
	_outputConfigFile = file;
}

void Parameters::setOutputUnpackedFile(const std::string& file)
{
	_outputUnpackedFile = file;
}

void Parameters::setOrdinalNumbersDirectory(const std::string& n)
{
	_ordinalNumbersDirectory = n;
}

void Parameters::setInputFile(const std::string& file)
{
	_inputFile = file;
}

void Parameters::setInputPdbFile(const std::string& file)
{
	_inputPdbFile = file;
}

void Parameters::setMaxMemoryLimit(uint64_t limit)
{
	_maxMemoryLimit = limit;
}

void Parameters::setMaxMemoryLimitHalfRam(bool f)
{
	_maxMemoryLimitHalfRam = f;
}

void Parameters::setEntryPoint(const retdec::common::Address& a)
{
	_entryPoint = a;
}
void Parameters::setMainAddress(const retdec::common::Address& a)
{
	_mainAddress = a;
}

void Parameters::setSectionVMA(const retdec::common::Address& a)
{
	_sectionVMA = a;
}

void Parameters::setBackendDisabledOpts(const std::string& o)
{
	_backendDisabledOpts = o;
}

void Parameters::setIsBackendNoOpts(bool b)
{
	_backendNoOpts = b;
}

void Parameters::setIsDetectStaticCode(bool b)
{
	_detectStaticCode = b;
}

const std::string& Parameters::getOrdinalNumbersDirectory() const
{
	return _ordinalNumbersDirectory;
}

const std::string& Parameters::getInputFile() const
{
	return _inputFile;
}

const std::string& Parameters::getInputPdbFile() const
{
	return _inputPdbFile;
}

const std::string& Parameters::getOutputFile() const
{
	return _outputFile;
}

const std::string& Parameters::getOutputBitcodeFile() const
{
	return _outputBitcodeFile;
}

const std::string& Parameters::getOutputAsmFile() const
{
	return _outputAsmFile;
}

const std::string& Parameters::getOutputLlvmirFile() const
{
	return _outputLlFile;
}

const std::string& Parameters::getOutputConfigFile() const
{
	return _outputConfigFile;
}

const std::string& Parameters::getOutputUnpackedFile() const
{
	return _outputUnpackedFile;
}

uint64_t Parameters::getMaxMemoryLimit() const
{
	return _maxMemoryLimit;
}

retdec::common::Address Parameters::getEntryPoint() const
{
	return _entryPoint;
}

retdec::common::Address Parameters::getMainAddress() const
{
	return _mainAddress;
}

retdec::common::Address Parameters::getSectionVMA() const
{
	return _sectionVMA;
}

const std::string& Parameters::getBackendDisabledOpts() const
{
	return _backendDisabledOpts;
}

void fixPath(std::string& path, utils::FilesystemPath root)
{
	utils::FilesystemPath p(path);
	if (p.isRelative())
	{
		root.append(p.getPath());
		path = root.getAbsolutePath();
	}
}

void fixPaths(std::set<std::string>& set, utils::FilesystemPath root)
{
	std::set<std::string> nset;

	for (auto p : set)
	{
		fixPath(p, root);
		nset.insert(p);
	}

	set = nset;
}

void Parameters::fixRelativePaths(const std::string& configPath)
{
	utils::FilesystemPath c(configPath);

	fixPaths(userStaticSignaturePaths, c);
	fixPaths(staticSignaturePaths, c);
	fixPaths(libraryTypeInfoPaths, c);
	fixPaths(abiPaths, c);
	fixPaths(cryptoPatternPaths, c);
	fixPath(_ordinalNumbersDirectory, c);
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
	serdes::serializeString(writer, JSON_ordinalNumDir, getOrdinalNumbersDirectory());

	serdes::serializeString(writer, JSON_inputFile, getInputFile());
	serdes::serializeString(writer, JSON_inputPdbFile, getInputPdbFile());
	serdes::serializeString(writer, JSON_outputFile, getOutputFile());
	serdes::serializeString(writer, JSON_outputBitcodeFile, getOutputBitcodeFile());
	serdes::serializeString(writer, JSON_outputAsmFile, getOutputAsmFile());
	serdes::serializeString(writer, JSON_outputLlFile, getOutputLlvmirFile());
	serdes::serializeString(writer, JSON_outputConfigFile, getOutputConfigFile());
	serdes::serializeString(writer, JSON_outputUnpackedFile, getOutputUnpackedFile());

	serdes::serializeString(writer, JSON_backendDisabledOpts, getBackendDisabledOpts());
	serdes::serializeBool(writer, JSON_backendNoOpts, isBackendNoOpts());
	serdes::serializeBool(writer, JSON_detectStaticCode, isDetectStaticCode());

	serdes::serializeContainer(writer, JSON_selectedRanges, selectedRanges);
	serdes::serializeContainer(writer, JSON_userStaticSigPaths, userStaticSignaturePaths);
	serdes::serializeContainer(writer, JSON_staticSigPaths, staticSignaturePaths);
	serdes::serializeContainer(writer, JSON_libraryTypeInfoPaths, libraryTypeInfoPaths);
	serdes::serializeContainer(writer, JSON_cryptoPatternPaths, cryptoPatternPaths);
	serdes::serializeContainer(writer, JSON_abiPaths, abiPaths);
	serdes::serializeContainer(writer, JSON_selectedFunctions, selectedFunctions);
	serdes::serializeContainer(writer, JSON_selectedNotFoundFncs, selectedNotFoundFunctions);
	serdes::serializeContainer(writer, JSON_llvmPasses, llvmPasses);

	serdes::serialize(writer, JSON_entryPoint, getEntryPoint());
	serdes::serialize(writer, JSON_mainAddress, getMainAddress());
	serdes::serialize(writer, JSON_sectionVMA, getSectionVMA());

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

	setInputFile( serdes::deserializeString(val, JSON_inputFile) );
	setInputPdbFile( serdes::deserializeString(val, JSON_inputPdbFile) );
	setOutputFile( serdes::deserializeString(val, JSON_outputFile) );
	setOutputBitcodeFile( serdes::deserializeString(val, JSON_outputBitcodeFile) );
	setOutputAsmFile( serdes::deserializeString(val, JSON_outputAsmFile) );
	setOutputLlvmirFile( serdes::deserializeString(val, JSON_outputLlFile) );
	setOutputConfigFile( serdes::deserializeString(val, JSON_outputConfigFile) );
	setOutputUnpackedFile( serdes::deserializeString(val, JSON_outputUnpackedFile) );

	setBackendDisabledOpts( serdes::deserializeString(val, JSON_backendDisabledOpts) );
	setIsBackendNoOpts( serdes::deserializeBool(val, JSON_backendNoOpts, false) );
	setIsDetectStaticCode( serdes::deserializeBool(val, JSON_detectStaticCode, true) );

	serdes::deserialize(val, JSON_entryPoint, _entryPoint);
	serdes::deserialize(val, JSON_mainAddress, _mainAddress);
	serdes::deserialize(val, JSON_sectionVMA, _sectionVMA);

	serdes::deserializeContainer(val, JSON_selectedRanges, selectedRanges);
	serdes::deserializeContainer(val, JSON_staticSigPaths, staticSignaturePaths);
	serdes::deserializeContainer(val, JSON_userStaticSigPaths, userStaticSignaturePaths);
	serdes::deserializeContainer(val, JSON_libraryTypeInfoPaths, libraryTypeInfoPaths);
	serdes::deserializeContainer(val, JSON_cryptoPatternPaths, cryptoPatternPaths);
	serdes::deserializeContainer(val, JSON_abiPaths, abiPaths);
	serdes::deserializeContainer(val, JSON_selectedFunctions, selectedFunctions);
	serdes::deserializeContainer(val, JSON_selectedNotFoundFncs, selectedNotFoundFunctions);
	serdes::deserializeContainer(val, JSON_llvmPasses, llvmPasses);
}

} // namespace config
} // namespace retdec
