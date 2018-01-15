/**
 * @file src/fileinfo/file_presentation/getters/simple_getter/header_plain_getter.cpp
 * @brief Methods of HeaderPlainGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/simple_getter/header_plain_getter.h"

using namespace retdec::fileformat;

namespace fileinfo {

/**
 * Constructor
 * @param fileInfo Information about file
 */
HeaderPlainGetter::HeaderPlainGetter(FileInformation &fileInfo) : SimpleGetter(fileInfo)
{

}

/**
 * Destructor
 */
HeaderPlainGetter::~HeaderPlainGetter()
{

}

std::size_t HeaderPlainGetter::loadInformation(std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	desc.clear();
	info.clear();

	desc.push_back("File status                            : ");
	desc.push_back("File version                           : ");
	desc.push_back("File header version                    : ");
	desc.push_back("Timestamp                              : ");
	desc.push_back("Number of bits in one byte             : ");
	desc.push_back("Number of bits in one word             : ");
	desc.push_back("OS/ABI                                 : ");
	desc.push_back("OS/ABI version                         : ");
	desc.push_back("Size of file header                    : ");
	desc.push_back("Table of segments offset               : ");
	desc.push_back("Size of one entry in table of segments : ");
	desc.push_back("Size of table of segments              : ");
	desc.push_back("Declared number of segments            : ");
	desc.push_back("Table of sections offset               : ");
	desc.push_back("Size of one entry in table of sections : ");
	desc.push_back("Size of table of sections              : ");
	desc.push_back("Declared number of sections            : ");
	desc.push_back("Size of COFF file header               : ");
	desc.push_back("Size of optional header                : ");
	desc.push_back("Checksum                               : ");
	desc.push_back("Size of the stack to reserve           : ");
	desc.push_back("Size of the stack to commit            : ");
	desc.push_back("Size of the local heap space to reserve: ");
	desc.push_back("Size of the local heap space to commit : ");
	desc.push_back("Declared number of data directories    : ");
	desc.push_back("Declared number of symbol tables       : ");
	if (fileinfo.isSignaturePresent())
		desc.push_back("Signature verified                     : ");

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
		info.push_back(fileinfo.isSignatureVerifiedStr("Yes", "No"));

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
void HeaderPlainGetter::getFileFlags(std::string &title, std::string &flags, std::vector<std::string> &desc, std::vector<std::string> &abbv) const
{
	title = "File flags                             : ";
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
void HeaderPlainGetter::getDllFlags(std::string &title, std::string &flags, std::vector<std::string> &desc, std::vector<std::string> &abbv) const
{
	title = "DLL flags                              : ";
	flags = fileinfo.getDllFlagsStr();
	fileinfo.getDllFlagsDescriptors(desc, abbv);
}

} // namespace fileinfo
