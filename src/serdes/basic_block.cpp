/**
 * @file src/serdes/basic_block.cpp
 * @brief Basic block (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <rapidjson/prettywriter.h>
#include <rapidjson/stringbuffer.h>

#include "retdec/common/basic_block.h"
#include "retdec/serdes/address.h"
#include "retdec/serdes/basic_block.h"
#include "retdec/serdes/std.h"

namespace {

const std::string JSON_startAddr  = "startAddr";
const std::string JSON_endAddr    = "endAddr";
const std::string JSON_preds      = "preds";
const std::string JSON_succs      = "succs";
const std::string JSON_srcAddr    = "srcAddr";
const std::string JSON_targetAddr = "targetAddr";
const std::string JSON_calls      = "calls";

} // anonymous namespace

namespace retdec {
namespace serdes {

template <typename Writer>
void serialize(Writer& writer, const common::BasicBlock::CallEntry& ce)
{
	writer.StartObject();
	serialize(writer, JSON_srcAddr, ce.srcAddr);
	serialize(writer, JSON_targetAddr, ce.targetAddr);
	writer.EndObject();
}
SERIALIZE_EXPLICIT_INSTANTIATION(common::BasicBlock::CallEntry)

void deserialize(const rapidjson::Value& val, common::BasicBlock::CallEntry& ce)
{
	if (val.IsNull() || !val.IsObject())
	{
		return;
	}

	deserialize(val, JSON_srcAddr, ce.srcAddr);
	deserialize(val, JSON_targetAddr, ce.targetAddr);
}

template <typename Writer>
void serialize(Writer& writer, const common::BasicBlock& bb)
{
	writer.StartObject();

	serialize(writer, JSON_startAddr, bb.getStart());
	serialize(writer, JSON_endAddr, bb.getEnd());

	serializeContainer(writer, JSON_preds, bb.preds);
	serializeContainer(writer, JSON_succs, bb.succs);
	serializeContainer(writer, JSON_calls, bb.calls);

	writer.EndObject();
}
SERIALIZE_EXPLICIT_INSTANTIATION(common::BasicBlock)

void deserialize(const rapidjson::Value& val, common::BasicBlock& bb)
{
	if (val.IsNull() || !val.IsObject())
	{
		return;
	}

	common::Address s;
	deserialize(val, JSON_startAddr, s);
	bb.setStart(s);

	common::Address e;
	deserialize(val, JSON_endAddr, e);
	bb.setEnd(e);

	deserializeContainer(val, JSON_preds, bb.preds);
	deserializeContainer(val, JSON_succs, bb.succs);
	deserializeContainer(val, JSON_calls, bb.calls);
}

} // namespace serdes
} // namespace retdec
