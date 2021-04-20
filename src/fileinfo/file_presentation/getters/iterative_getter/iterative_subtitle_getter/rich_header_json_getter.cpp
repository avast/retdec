/**
 * @file src/fileinfo/file_presentation/getters/iterative_getter/iterative_subtitle_getter/rich_header_json_getter.cpp
 * @brief Methods of RichHeaderJsonGetter class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/fileformat/utils/conversions.h"
#include "fileinfo/file_presentation/getters/iterative_getter/iterative_subtitle_getter/rich_header_json_getter.h"

using namespace retdec::utils;
using namespace retdec::fileformat;

namespace retdec {
namespace fileinfo {

/**
 * Constructor
 * @param fileInfo Information about file
 */
RichHeaderJsonGetter::RichHeaderJsonGetter(FileInformation &fileInfo) : IterativeSubtitleGetter(fileInfo)
{
	numberOfStructures = 1;
	numberOfStoredRecords.push_back(fileinfo.getNumberOfStoredRecordsInRichHeader());
	numberOfExtraElements.push_back(0);
	title = "richHeader";
	subtitle = "richHeaderRecords";
	commonHeaderElements.push_back("index");
	commonHeaderElements.push_back("product_id");
	commonHeaderElements.push_back("count");
	commonHeaderElements.push_back("product_name");
	commonHeaderElements.push_back("vs_name");
}

std::size_t RichHeaderJsonGetter::getBasicInfo(std::size_t structIndex, std::vector<std::string> &desc, std::vector<std::string> &info) const
{
	if(structIndex >= numberOfStructures || !fileinfo.hasRichHeaderRecords())
	{
		return 0;
	}

	desc.clear();
	info.clear();

	desc.push_back("offset");
	desc.push_back("key");
	desc.push_back("signature");
	desc.push_back("crc32");
	desc.push_back("md5");
	desc.push_back("sha256");
	desc.push_back("numberOfRecords");
	desc.push_back("rawBytes");

	info.push_back(fileinfo.getRichHeaderOffsetStr(hexWithPrefix));
	info.push_back(fileinfo.getRichHeaderKeyStr(hexWithPrefix));
	info.push_back(toLower(fileinfo.getRichHeaderSignature()));
	info.push_back(fileinfo.getRichHeaderCrc32());
	info.push_back(fileinfo.getRichHeaderMd5());
	info.push_back(fileinfo.getRichHeaderSha256());
	info.push_back(std::to_string(fileinfo.getNumberOfStoredRecordsInRichHeader()));
	info.push_back(replaceNonprintableChars(fileinfo.getRichHeaderRawBytesStr()));

	return info.size();
}

bool RichHeaderJsonGetter::getRecord(std::size_t structIndex, std::size_t recIndex, std::vector<std::string> &record) const
{
	if(structIndex >= numberOfStructures || recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	record.clear();
	record.push_back(std::to_string(recIndex));
	const auto productId = fileinfo.getRichHeaderRecordProductIdStr(recIndex);
	const auto productBuild = fileinfo.getRichHeaderRecordProductBuildStr(recIndex);
	record.push_back(!productId.empty() && !productBuild.empty() ? productId + "." + productBuild : "");
	record.push_back(fileinfo.getRichHeaderRecordNumberOfUsesStr(recIndex));
	record.push_back(fileinfo.getRichHeaderRecordProductNameStr(recIndex));
	record.push_back(fileinfo.getRichHeaderRecordVisualStudioNameStr(recIndex));

	return true;
}

bool RichHeaderJsonGetter::getFlags(std::size_t structIndex, std::size_t recIndex, std::string &flagsValue, std::vector<std::string> &desc) const
{
	if(structIndex >= numberOfStructures || recIndex >= numberOfStoredRecords[structIndex])
	{
		return false;
	}

	flagsValue.clear();
	desc.clear();

	return true;
}

} // namespace fileinfo
} // namespace retdec
