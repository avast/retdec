/**
 * @file include/retdec/common/basic_block.h
 * @brief Common basic block representation.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_COMMON_BASIC_BLOCK_H
#define RETDEC_COMMON_BASIC_BLOCK_H

#include <set>
#include <tuple>

#include "retdec/common/address.h"
#include "retdec/common/range.h"

namespace retdec {
namespace common {

class BasicBlock : public AddressRange
{
	public:
		using AddressRange::AddressRange;

	public:
		/// Start addresses of predecessor basic blocks.
		std::set<Address> preds;
		/// Start addresses of successor basic blocks.
		std::set<Address> succs;

		/// All the calls in this basic block.
		struct CallEntry
		{
			Address srcAddr;
			Address targetAddr;

			bool operator<(const CallEntry& o) const
			{
				return std::tie(srcAddr, targetAddr)
						< std::tie(o.srcAddr, o.targetAddr);
			}
		};
		std::set<CallEntry> calls;
};

} // namespace common
} // namespace retdec

#endif
