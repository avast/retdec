/**
 * @file src/fileinfo/file_presentation/getters/simple_getter/header_json_getter.cpp
 * @brief Methods of HeaderJsonGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/simple_getter/header_json_getter.h"

using namespace retdec::fileformat;

namespace fileinfo {

/**
 * Constructor
 * @param fileInfo Information about file
 */
HeaderJsonGetter::HeaderJsonGetter(FileInformation &fileInfo) : SimpleGetter(fileInfo)
{

}

/**
 * Destructor
 */
HeaderJsonGetter::~HeaderJsonGetter()
{

}

std::size_t HeaderJsonGetter::loadInformation(std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	desc.clear();
	info.clear();

	desc.push_back("fileStatus");
	desc.push_back("fileVersion");
	desc.push_back("fileHeaderVersion");
	desc.push_back("timestamp");
	desc.push_back("numberOfBitsInOneByte");
	desc.push_back("numberOfBitsInOneWord");
	desc.push_back("osOrAbi");
	desc.push_back("osOrAbiVersion");
	desc.push_back("sizeOfFileHeader");
	desc.push_back("tableOfSegmentsOffset");
	desc.push_back("sizeOfOneEntryInTableOfSegments");
	desc.push_back("sizeOfTableOfSegments");
	desc.push_back("declaredNumberOfSegments");
	desc.push_back("tableOfSectionsOffset");
	desc.push_back("sizeOfOneEntryInTableOfSections");
	desc.push_back("sizeOfTableOfSections");
	desc.push_back("declaredNumberOfSections");
	desc.push_back("sizeOfCoffFileHeader");
	desc.push_back("sizeOfOptionalHeader");
	desc.push_back("checksum");
	desc.push_back("sizeOfTheStackToReserve");
	desc.push_back("sizeOfTheStackToCommit");
	desc.push_back("sizeOfTheLocalHeapSpaceToReserve");
	desc.push_back("sizeOfTheLocalHeapSpaceToCommit");
	desc.push_back("declaredNumberOfDataDirectories");
	desc.push_back("declaredNumberOfSymbolTables");
	if (fileinfo.isSignaturePresent())
		desc.push_back("signatureVerified");

	info.push_back(fileinfo.getFileStatus());
	info.push_back(fileinfo.getFileVersion());
	info.push_back(fileinfo.getFileHeaderVersion());
	info.push_back(fileinfo.getTimeStamp());
	info.push_back(fileinfo.getNumberOfBitsInByteStr());
	info.push_back(fileinfo.getNumberOfBitsInWordStr());
	info.push_back(fileinfo.getOsAbi());
	info.push_back(fileinfo.getOsAbiVersion());
	info.push_back(fileinfo.getFileHeaderSizeStr(hexWithPrefix));
	info.push_back(fileinfo.getSegmentTableOffsetStr(hexWithPrefix));
	info.push_back(fileinfo.getSegmentTableEntrySizeStr(hexWithPrefix));
	info.push_back(fileinfo.getSegmentTableSizeStr(hexWithPrefix));
	info.push_back(fileinfo.getNumberOfDeclaredSegmentsStr());
	info.push_back(fileinfo.getSectionTableOffsetStr(hexWithPrefix));
	info.push_back(fileinfo.getSectionTableEntrySizeStr(hexWithPrefix));
	info.push_back(fileinfo.getSectionTableSizeStr(hexWithPrefix));
	info.push_back(fileinfo.getNumberOfDeclaredSectionsStr());
	info.push_back(fileinfo.getCoffFileHeaderSizeStr(hexWithPrefix));
	info.push_back(fileinfo.getOptionalHeaderSizeStr(hexWithPrefix));
	info.push_back(fileinfo.getChecksumStr());
	info.push_back(fileinfo.getStackReserveSizeStr(hexWithPrefix));
	info.push_back(fileinfo.getStackCommitSizeStr(hexWithPrefix));
	info.push_back(fileinfo.getHeapReserveSizeStr(hexWithPrefix));
	info.push_back(fileinfo.getHeapCommitSizeStr(hexWithPrefix));
	info.push_back(fileinfo.getNumberOfDeclaredDataDirectoriesStr());
	info.push_back(fileinfo.getNumberOfDeclaredSymbolTablesStr());
	if (fileinfo.isSignaturePresent())
		info.push_back(fileinfo.isSignatureVerifiedStr());

	return info.size();
}

/**
 * Get file flags
 * @param title Into this parameter name of flags is stored
 * @param flags Into this parameter flags are stored
 * @param desc Vector for save descriptors
 * @param abbv Vector for save abbreviations of descriptors
 *
 * It is guaranteed that the number of stored descriptors and abbreviations are the same
 */
void HeaderJsonGetter::getFileFlags(std::string &title, std::string &flags, std::vector<std::string> &desc, std::vector<std::string> &abbv) const
{
	title = "fileFlags";
	flags = fileinfo.getFileFlagsStr();
	fileinfo.getFileFlagsDescriptors(desc, abbv);
}

/**
 * Get DLL flags
 * @param title Into this parameter name of flags is stored
 * @param flags Into this parameter flags are stored
 * @param desc Vector for save descriptors
 * @param abbv Vector for save abbreviations of descriptors
 *
 * It is guaranteed that the number of stored descriptors and abbreviations are the same
 */
void HeaderJsonGetter::getDllFlags(std::string &title, std::string &flags, std::vector<std::string> &desc, std::vector<std::string> &abbv) const
{
	title = "dllFlags";
	flags = fileinfo.getDllFlagsStr();
	fileinfo.getDllFlagsDescriptors(desc, abbv);
}

} // namespace fileinfo
