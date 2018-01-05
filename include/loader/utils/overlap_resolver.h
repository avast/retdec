/**
 * @file include/loader/utils/overlap_resolver.h
 * @brief Declaration of overlap resolver.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef LOADER_UTILS_OVERLAP_RESOLVER_H
#define LOADER_UTILS_OVERLAP_RESOLVER_H

#include <cstdint>
#include <functional>
#include <vector>

#include "tl-cpputils/range.h"
#include "loader/utils/range.h"

namespace loader {

/**
 * Defines different type of overlaps that can happen.
 */
enum class Overlap
{
	None, ///< No overlap.
	OverStart, ///< Overlap over starting value.
	InMiddle, ///< Overlap somewhere in the middle of the range.
	OverEnd, ///< Overlap over ending value.
	Full ///< Full overlap of one range over another.
};

class OverlapResolver
{
public:
	class Result
	{
	public:
		Result(Overlap overlapType, const std::vector<tl_cpputils::Range<std::uint64_t>>& ranges);

		Overlap getOverlap() const;
		const std::vector<tl_cpputils::Range<std::uint64_t>>& getRanges() const;

	private:
		Overlap _overlap;
		std::vector<tl_cpputils::Range<std::uint64_t>> _ranges;
	};

	OverlapResolver() = delete;

	static OverlapResolver::Result resolve(const tl_cpputils::Range<std::uint64_t>& first, const tl_cpputils::Range<std::uint64_t>& second);
};

} // namespace loader

#endif
