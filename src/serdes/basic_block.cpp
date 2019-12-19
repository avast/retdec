/**
 * @file src/serdes/basic_block.cpp
 * @brief Basic block (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#include <algorithm>
#include <vector>

#include "retdec/common/basic_block.h"
#include "retdec/serdes/address.h"
#include "retdec/serdes/basic_block.h"
#include "retdec/serdes/std.h"

#include "serdes/utils.h"

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

Json::Value serialize(const common::BasicBlock::CallEntry& ce)
{
	Json::Value e;

	e[JSON_srcAddr] = serdes::serialize(ce.srcAddr);
	e[JSON_targetAddr] = serdes::serialize(ce.targetAddr);

	return e;
}

void deserialize(const Json::Value& val, common::BasicBlock::CallEntry& ce)
{
	if (val.isNull() || !val.isObject())
	{
		return;
	}

	serdes::deserialize(val[JSON_srcAddr], ce.srcAddr);
	serdes::deserialize(val[JSON_targetAddr], ce.targetAddr);
}

Json::Value serialize(const common::BasicBlock& bb)
{
	Json::Value b;

	b[JSON_startAddr] = serdes::serialize(bb.getStart());

	if (bb.getEnd().isDefined())
	{
		b[JSON_endAddr] = serdes::serialize(bb.getEnd());
	}
	if (!bb.preds.empty())
	{
		b[JSON_preds] = serdes::serialize(bb.preds);
	}
	if (!bb.succs.empty())
	{
		b[JSON_succs] = serdes::serialize(bb.succs);
	}
	if (!bb.calls.empty())
	{
		b[JSON_calls] = serdes::serialize(bb.calls);
	}

	return b;
}

void deserialize(const Json::Value& val, common::BasicBlock& bb)
{
	if (val.isNull() || !val.isObject())
	{
		return;
	}

	common::Address s;
	serdes::deserialize(val[JSON_startAddr], s);
	bb.setStart(s);

	common::Address e;
	serdes::deserialize(val[JSON_endAddr], e);
	bb.setEnd(e);

	serdes::deserialize(val[JSON_preds], bb.preds);
	serdes::deserialize(val[JSON_succs], bb.succs);
	serdes::deserialize(val[JSON_calls], bb.calls);
}

} // namespace serdes
} // namespace retdec
