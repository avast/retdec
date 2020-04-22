/**
 * @file src/serdes/file_format.cpp
 * @brief File format (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>

#include "retdec/common/file_format.h"
#include "retdec/serdes/file_format.h"
#include "retdec/serdes/std.h"

namespace {

const std::string JSON_name    = "name";
const std::string JSON_endian  = "endian";
const std::string JSON_bitSize = "bitSize";

const std::string JSON_val_little = "little";
const std::string JSON_val_big    = "big";

} // anonymous namespace

namespace retdec {
namespace serdes {

template <typename Writer>
void serialize(Writer& writer, const common::FileFormat& ff)
{
	if (ff.getFileClassBits())
	{
		writer.String(ff.getName() + std::to_string(ff.getFileClassBits()));
	}
	else
	{
		writer.String(ff.getName());
	}
}
SERIALIZE_EXPLICIT_INSTANTIATION(common::FileFormat)

void deserialize(const rapidjson::Value& val, common::FileFormat& ff)
{
	if (val.IsNull() || !val.IsString())
	{
		return;
	}
	ff.setName(val.GetString());
}

} // namespace serdes
} // namespace retdec
