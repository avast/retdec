/**
 * @file src/fileinfo/file_detector/raw_data_detector.cpp
 * @brief Definition of @c RawDataDetector class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/file_format/raw_data/raw_data_format.h"
#include "fileinfo/file_detector/raw_data_detector.h"

using namespace retdec::cpdetect;
using namespace retdec::fileformat;

namespace fileinfo {

/**
 * Constructor
 * @param pathToInputFile Path to input file
 * @param finfo Instance of class for storing information about file
 * @param searchPar Parameters for detection of used compiler (or packer)
 * @param loadFlags Load flags
 */
RawDataDetector::RawDataDetector(std::string pathToInputFile, FileInformation &finfo,
	retdec::cpdetect::DetectParams &searchPar, retdec::fileformat::LoadFlags loadFlags) :
	FileDetector(pathToInputFile, finfo, searchPar, loadFlags)
{
	fileParser = rawParser = std::make_shared<retdec::fileformat::RawDataFormat>(pathToInputFile, loadFlags);
	loaded = fileParser->isInValidState();
}

/**
 * Destructor
 */
RawDataDetector::~RawDataDetector()
{

}

/**
 * Get information about sections
 */
void RawDataDetector::getSection()
{
	fileInfo.setNumberOfDeclaredSections(1);

	const auto *sec = fileParser->getSections()[0];
	if(!sec)
	{
		return;
	}

	FileSection fs;
	fs.setCrc32(sec->getCrc32());
	fs.setMd5(sec->getMd5());
	fs.setSha256(sec->getSha256());
	fs.setName(sec->getName());
	fs.setIndex(sec->getIndex());
	fs.setStartAddress(sec->getAddress());
	fs.setOffset(sec->getOffset());
	fs.setSizeInFile(sec->getSizeInFile());
	fs.clearFlagsDescriptors();

	unsigned long long aux = 0;
	if(sec->getSizeInMemory(aux))
	{
		fs.setSizeInMemory(aux);
	}
	if(sec->getSizeOfOneEntry(aux))
	{
		fs.setEntrySize(aux);
	}

	fileInfo.addSection(fs);
}

void RawDataDetector::detectFileClass()
{
	// unknown -- nothing is set
}

void RawDataDetector::detectArchitecture()
{
	if(!fileConfig || fileConfig->architecture.isUnknown())
	{
		return;
	}

	switch(fileParser->getTargetArchitecture())
	{
		case Architecture::X86:
			fileInfo.setTargetArchitecture("x86");
			break;
		case Architecture::X86_64:
			fileInfo.setTargetArchitecture("x86-64");
			break;
		case Architecture::ARM:
			fileInfo.setTargetArchitecture("ARM");
			break;
		case Architecture::POWERPC:
			fileInfo.setTargetArchitecture("PowerPC");
			break;
		case Architecture::MIPS:
			fileInfo.setTargetArchitecture("MIPS");
			break;
		case Architecture::UNKNOWN:
		default:;
	}
}

void RawDataDetector::detectFileType()
{
	if(fileParser->isDll())
	{
		fileInfo.setFileType("DLL");
	}
	else if(fileParser->isExecutable())
	{
		fileInfo.setFileType("Executable file");
	}
	else if(fileParser->isObjectFile())
	{
		fileInfo.setFileType("Relocatable file");
	}
}

void RawDataDetector::getAdditionalInfo()
{
	unsigned long long ep = 0;
	if(fileParser->getEpAddress(ep))
	{
		fileInfo.toolInfo.epAddress = ep;
		fileInfo.toolInfo.entryPointAddress = true;
	}
	getSection();
}

retdec::cpdetect::CompilerDetector* RawDataDetector::createCompilerDetector() const
{
	if(cpParams.searchType == SearchType::EXACT_MATCH)
	{
		cpParams.searchType = SearchType::MOST_SIMILAR;
	}

	return new RawDataCompiler(*rawParser, cpParams, fileInfo.toolInfo);
}

} // namespace fileinfo
