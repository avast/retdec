/**
 * @file include/retdec/serdes/basic_block.h
 * @brief Basic block (de)serialization.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_SERDES_BASIC_BLOCK_H
#define RETDEC_SERDES_BASIC_BLOCK_H

#include <json/json.h>

namespace retdec {

namespace common {
class BasicBlock;
} // namespace common

namespace serdes {

Json::Value serialize(const common::BasicBlock::CallEntry& ce);
void deserialize(const Json::Value& val, common::BasicBlock::CallEntry& ce);

Json::Value serialize(const common::BasicBlock& bb);
void deserialize(const Json::Value& val, common::BasicBlock& bb);

} // namespace serdes
} // namespace retdec

#endif