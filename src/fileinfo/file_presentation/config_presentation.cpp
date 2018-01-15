/**
 * @file src/fileinfo/file_presentation/config_presentation.cpp
 * @brief Config DB presentation class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "fileinfo/file_presentation/config_presentation.h"
#include "fileinfo/file_presentation/getters/pattern_config_getter/pattern_config_getter.h"

using namespace retdec::config;
using namespace retdec::utils;
using namespace retdec::cpdetect;
using namespace retdec::fileformat;

namespace fileinfo {

/**
 * Constructor
 * @param fileinfo_ Information about file
 * @param file_ Name of configuration file
 */
ConfigPresentation::ConfigPresentation(FileInformation &fileinfo_, std::string file_) :
	FilePresentation(fileinfo_), configFile(file_), stateIsValid(true)
{
	try
	{
		outDoc.readJsonFile(configFile);
	}
	catch (const FileNotFoundException&)
	{
		// file does not exist, it will be created at the end.
	}
	catch (const ParseException &e)
	{
		stateIsValid = false;
		errorMessage = e.what();
	}
}

/**
 * Destructor
 */
ConfigPresentation::~ConfigPresentation()
{
	outDoc.generateJsonFile(configFile);
}

/**
 * Present information about used compiler or packer
 * Method presents only first detected tool
 */
void ConfigPresentation::presentCompiler()
{
	const std::size_t noOfCompilers = fileinfo.getNumberOfDetectedCompilers();
	if(!noOfCompilers)
	{
		return;
	}

	bool similarityFlag = false, actualSimilarity;
	double percentage = 0.0;
	bool heuristics;
	outDoc.tools.clear();

	for(std::size_t i = 0; i < noOfCompilers; ++i)
	{
		const auto& detectedTool = fileinfo.toolInfo.detectedTools[i];

		if(detectedTool.source == DetectionMethod::SIGNATURE)
		{
			heuristics = false;
			actualSimilarity = (detectedTool.agreeCount != detectedTool.impCount);
			if(actualSimilarity)
			{
				if(similarityFlag)
				{
					continue;
				}
				similarityFlag = true;
			}
		}
		else
		{
			heuristics = true;
		}

		ToolInfo ci;
		ci.setName(toLower(detectedTool.name));
		ci.setType(toLower(toolTypeToString(detectedTool.type)));
		ci.setVersion(toLower(detectedTool.versionInfo));
		ci.setAdditionalInfo(detectedTool.additionalInfo);

		if(detectedTool.impCount)
		{
			percentage = static_cast<double>(detectedTool.agreeCount) / detectedTool.impCount * 100;
		}
		else
		{
			percentage = 0.0;
		}
		ci.setPercentage(percentage);
		ci.setIdenticalSignificantNibbles(detectedTool.agreeCount);
		ci.setTotalSignificantNibbles(detectedTool.impCount);
		ci.setIsFromHeuristics(heuristics);

		outDoc.tools.insert(ci);
	}
}

/**
 * Present information about original programming language(s)
 */
void ConfigPresentation::presentLanguages()
{
	const auto noOfLanguages = fileinfo.toolInfo.detectedLanguages.size();
	if(!noOfLanguages)
	{
		return;
	}
	outDoc.languages.clear();

	for(std::size_t i = 0; i < noOfLanguages; ++i)
	{
		Language l(fileinfo.toolInfo.detectedLanguages[i].name);
		l.setIsBytecode(fileinfo.toolInfo.detectedLanguages[i].bytecode);

		outDoc.languages.insert(l);
	}
}

/**
 * Present information about detected patterns
 */
void ConfigPresentation::presentPatterns()
{
	PatternConfigGetter(fileinfo, &outDoc);
}

bool ConfigPresentation::present()
{
	if(!stateIsValid)
	{
		return false;
	}
	else if(returnCode == ReturnCode::FILE_PROBLEM || returnCode == ReturnCode::UNKNOWN_FORMAT || returnCode == ReturnCode::FILE_NOT_EXIST)
	{
		return true;
	}

	outDoc.setInputFile(fileinfo.getPathToFile());

	if(fileinfo.getFileFormatEnum() == Format::ELF)
	{
		outDoc.fileFormat.setIsElf();
	}
	else if(fileinfo.getFileFormatEnum() == Format::PE)
	{
		outDoc.fileFormat.setIsPe();
	}
	else if(fileinfo.getFileFormatEnum() == Format::COFF)
	{
		outDoc.fileFormat.setIsCoff();
	}
	else if(fileinfo.getFileFormatEnum() == Format::MACHO)
	{
		outDoc.fileFormat.setIsMacho();
	}
	else if(fileinfo.getFileFormatEnum() == Format::INTEL_HEX)
	{
		outDoc.fileFormat.setIsIntelHex();
	}
	else if(fileinfo.getFileFormatEnum() == Format::RAW_DATA)
	{
		outDoc.fileFormat.setIsRaw();
	}
	else
	{
		outDoc.fileFormat.setIsUnknown();
	}

	const auto ft = fileinfo.getFileType();
	if(ft == "Executable file")
	{
		outDoc.fileType.setIsExecutable();
	}
	else if(ft == "DLL")
	{
		outDoc.fileType.setIsShared();
	}
	else if(ft == "Relocatable file")
	{
		outDoc.fileType.setIsObject();
	}
	else
	{
		outDoc.fileType.setIsUnknown();
	}

	const auto fc = fileinfo.getFileClass();
	if(fc == "32-bit")
	{
		outDoc.fileFormat.setIs32bit();
	}
	else if(fc == "64-bit")
	{
		outDoc.fileFormat.setIs64bit();
	}

	outDoc.architecture.setName(toLower(fileinfo.getTargetArchitecture()));
	unsigned long long bitsInWord;
	if(strToNum(fileinfo.getNumberOfBitsInWordStr(), bitsInWord))
	{
		outDoc.architecture.setBitSize(bitsInWord);
	}

	const auto fe = fileinfo.getEndianness();
	if(fe == "Little endian")
	{
		outDoc.architecture.setIsEndianLittle();
	}
	else if(fe == "Big endian")
	{
		outDoc.architecture.setIsEndianBig();
	}
	else
	{
		outDoc.architecture.setIsEndianUnknown();
	}

	if(fileinfo.toolInfo.entryPointAddress)
	{
		outDoc.setEntryPoint(fileinfo.toolInfo.epAddress);
	}
	if(!fileinfo.getImageBaseStr(std::dec).empty())
	{
		outDoc.setImageBase(fileinfo.toolInfo.imageBase);
	}

	presentCompiler();
	presentLanguages();
	presentPatterns();
	return true;
}

/**
 * Get error message
 * @return Error message or empty string if presentation went OK
 */
std::string ConfigPresentation::getErrorMessage() const
{
	return errorMessage;
}

} // namespace fileinfo
