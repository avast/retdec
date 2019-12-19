/**
 * @file src/serdes/file_format.cpp
 * @brief File format (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include "retdec/common/file_format.h"
#include "retdec/serdes/file_format.h"

#include "serdes/utils.h"

namespace {

const std::string JSON_name    = "name";
const std::string JSON_endian  = "endian";
const std::string JSON_bitSize = "bitSize";

const std::string JSON_val_little = "little";
const std::string JSON_val_big    = "big";

} // anonymous namespace

namespace retdec {
namespace serdes {

Json::Value serialize(const common::FileFormat& ff)
{
	if (ff.getFileClassBits())
		return ff.getName() + std::to_string(ff.getFileClassBits());
	else
		return ff.getName();
}

void deserialize(const Json::Value& val, common::FileFormat& ff)
{
	if (val.isNull())
	{
		return;
	}
	ff.setName(safeGetString(val));
}

} // namespace serdes
} // namespace retdec
