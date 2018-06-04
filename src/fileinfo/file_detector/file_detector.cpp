/**
 * @file src/fileinfo/file_detector/file_detector.cpp
 * @brief Methods of FileDetector class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <memory>

#include <tinyxml2.h>

#include "retdec/fileformat/file_format/file_format.h"
#include "fileinfo/file_detector/file_detector.h"
#include "retdec/loader/loader.h"

using namespace retdec::utils;
using namespace retdec::cpdetect;
using namespace retdec::fileformat;

namespace fileinfo {

/**
 * Constructor
 *
 * Constructor in subclass must initialize members @a fileParser and @a loaded.
 */
FileDetector::FileDetector(std::string pathToInputFile, FileInformation &finfo, retdec::cpdetect::DetectParams &searchPar, retdec::fileformat::LoadFlags loadFlags) :
	fileInfo(finfo), cpParams(searchPar), fileConfig(nullptr), fileParser(nullptr), loaded(false), loadFlags(loadFlags)
{
	fileInfo.setPathToFile(pathToInputFile);
}

/**
 * Destructor
 */
FileDetector::~FileDetector()
{

}

/**
 * Get information about endianness
 */
void FileDetector::getEndianness()
{
	switch(fileParser->getEndianness())
	{
		case Endianness::LITTLE:
			fileInfo.setEndianness("Little endian");
			break;
		case Endianness::BIG:
			fileInfo.setEndianness("Big endian");
			break;
		default:;
	}
}

/**
 * Get bit-size of target architecture
 */
void FileDetector::getArchitectureBitSize()
{
	const auto bitSize = fileParser->getWordLength();
	if(bitSize)
	{
		fileInfo.setNumberOfBitsInWord(bitSize);
	}
}

/**
 * Get all supported information about used compiler or packer
 */
void FileDetector::getCompilerInformation()
{
	std::unique_ptr<CompilerDetector> compDetector(createCompilerDetector());
	fileInfo.setStatus(compDetector ? compDetector->getAllInformation() : ReturnCode::UNKNOWN_CP);

	for(const auto &m : fileInfo.toolInfo.errorMessages)
	{
		fileInfo.messages.push_back(m);
	}
}

/**
 * Get information about rich header
 */
void FileDetector::getRichHeaderInfo()
{
	const auto *rich = fileParser->getRichHeader();
	fileInfo.setRichHeader(rich);
	if(rich)
	{
		unsigned long long key;
		if((!rich->getKey(key) && rich->getValidStructure()) ||
			// length of one record in table is 16 nibbles (2 dwords)
			rich->getSignatureLength() != rich->getNumberOfRecords() * 16)
		{
			fileInfo.messages.push_back("Warning: Rich header has invalid key.");
		}
		if(rich->getSuspicious())
		{
			fileInfo.messages.push_back("Warning: Rich header contains suspicious content.");
		}
	}
}

/**
 * Get information about overlay
 */
void FileDetector::getOverlayInfo()
{
	const auto size = fileParser->getOverlaySize();
	if(size)
	{
		fileInfo.setOverlayOffset(fileParser->getDeclaredFileLength());
		fileInfo.setOverlaySize(size);
	}
}

/**
 * Get information about related PDB file
 */
void FileDetector::getPdbInfo()
{
	const auto *pdb = fileParser->getPdbInfo();
	if(pdb)
	{
		fileInfo.setPdbType(pdb->getType());
		fileInfo.setPdbPath(pdb->getPath());
		fileInfo.setPdbGuid(pdb->getGuid());
		fileInfo.setPdbAge(pdb->getAge());
		fileInfo.setPdbTimeStamp(pdb->getTimeStamp());
	}
}

/**
 * Get information about resources
 */
void FileDetector::getResourceInfo()
{
	const auto *resTable = fileParser->getResourceTable();
	if(!resTable)
	{
		return;
	}

	for(const auto &dRes : *resTable)
	{
		Resource res;
		res.setCrc32(dRes.getCrc32());
		res.setMd5(dRes.getMd5());
		res.setSha256(dRes.getSha256());
		res.setName(dRes.getName());
		res.setType(dRes.getType());
		res.setLanguage(dRes.getLanguage());
		res.setOffset(dRes.getOffset());
		res.setSize(dRes.getSizeInFile());
		std::size_t aux;
		if(dRes.getNameId(aux))
		{
			res.setNameId(aux);
		}
		if(dRes.getTypeId(aux))
		{
			res.setTypeId(aux);
		}
		if(dRes.getLanguageId(aux))
		{
			res.setLanguageId(aux);
		}
		if(dRes.getSublanguageId(aux))
		{
			res.setSublanguageId(aux);
		}
		fileInfo.addResource(res);
	}
}

/**
 * Get information from manifest file
 */
void FileDetector::getManifestInfo()
{
	std::string str;
	tinyxml2::XMLDocument document;
	const auto *manifestRes = fileParser->getManifestResource();
	if(!manifestRes || !manifestRes->getString(str) || document.Parse(str.c_str(), str.length()) != tinyxml2::XML_SUCCESS)
	{
		return;
	}

	tinyxml2::XMLPrinter printer, compactPrinter(nullptr, true);
	document.Print(&printer);
	document.Print(&compactPrinter);
	fileInfo.setManifest(printer.CStr());
	fileInfo.setCompactManifest(compactPrinter.CStr());
}

/**
 * Get information about imports
 */
void FileDetector::getImports()
{
	fileInfo.setImportTable(fileParser->getImportTable());
}

/**
 * Get information about exports
 */
void FileDetector::getExports()
{
	fileInfo.setExportTable(fileParser->getExportTable());
}

/**
 * Get hashes of input file
 */
void FileDetector::getHashes()
{
	fileInfo.setCrc32(fileParser->getCrc32());
	fileInfo.setMd5(fileParser->getMd5());
	fileInfo.setSha256(fileParser->getSha256());
	fileInfo.setSectionTableCrc32(fileParser->getSectionTableCrc32());
	fileInfo.setSectionTableMd5(fileParser->getSectionTableMd5());
	fileInfo.setSectionTableSha256(fileParser->getSectionTableSha256());
}

/**
 * Get information about strings
 */
void FileDetector::getStrings()
{
	fileInfo.setStrings(&fileParser->getStrings());
}

/**
 * Get information about certificates
 */
void FileDetector::getCertificates()
{
	if (fileParser->isSignaturePresent())
		fileInfo.setSignatureVerified(fileParser->isSignatureVerified());
	fileInfo.setCertificateTable(fileParser->getCertificateTable());
}

/**
 * Get loader information
 */

void FileDetector::getLoaderInfo()
{
	// Propagate loader error no matter if the Image pointer will be created or not
	auto ldrErrInfo = getFileParser()->getLoaderErrorInfo();
	if (ldrErrInfo.loaderErrorCode != 0)
	{
		fileInfo.setLoaderErrorInfo(ldrErrInfo);
	}

	std::unique_ptr<retdec::loader::Image> image = retdec::loader::createImage(fileParser);
	if(!image)
	{
		return;
	}

	unsigned long long index = 0;
	fileInfo.setLoadedBaseAddress(image->getBaseAddress());

	for(const auto &segment : image->getSegments())
	{
		LoadedSegment loadedSegment(index++, segment->getName(), segment->getAddress(), segment->getSize());
		fileInfo.addLoadedSegment(loadedSegment);
	}

	if(!image->getStatusMessage().empty())
	{
		fileInfo.setLoaderStatusMessage(image->getStatusMessage());
	}
}

/**
 * @fn void FileDetector::detectFileClass()
 * Detect class of file
 */

/**
 * @fn void FileDetector::detectArchitecture()
 * Detect of target architecture
 */

/**
 * @fn void FileDetector::detectFileType()
 * Detect of type of file
 */

/**
 * @fn void FileDetector::getAdditionalInfo()
 * Get additional information about file
 */

/**
 * @fn retdec::cpdetect::CompilerDetector* FileDetector::createCompilerDetector() const
 * Factory for creating detector of compilers
 * @return Instance of compiler detector or nullptr if detection of compiler
 *    is not supported for actual file format
 */

/**
 * We use config to initialize loaded file format -- set architecture, endian etc.
 * Used for formats that are lacking some information that needs to be specified
 * by the user -- Intel HEX, raw data.
 * @param config Config.
 */
void FileDetector::setConfigFile(retdec::config::Config &config)
{
	fileConfig = &config;
	fileParser->initFromConfig(config);
}

/**
 * Get all supported information about binary file
 */
void FileDetector::getAllInformation()
{
	if(loaded)
	{
		fileInfo.setFileFormat(fileParser->getFileFormatName());
		detectFileClass();
		detectArchitecture();
		detectFileType();
		getEndianness();
		getArchitectureBitSize();
		getCompilerInformation();
		getRichHeaderInfo();
		getOverlayInfo();
		getPdbInfo();
		getResourceInfo();
		getManifestInfo();
		getImports();
		getExports();
		getHashes();
		getAdditionalInfo();
		getCertificates();
		getLoaderInfo();
		getStrings();
	}
}

/**
 * Get pointer to file parser
 * @return Pointer to file parser
 */
const retdec::fileformat::FileFormat* FileDetector::getFileParser() const
{
	return fileParser.get();
}

} // namespace fileinfo
