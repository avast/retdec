/**
 * @file src/loader/utils/overlap_resolver.cpp
 * @brief Definition of overlap resolver.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "retdec/loader/utils/overlap_resolver.h"

namespace retdec {
namespace loader {

/**
 * Constructor for OverlapResolver::Result.
 *
 * @param overlap The overlap type.
 * @param ranges The ranges to store in the result.
 */
OverlapResolver::Result::Result(Overlap overlap, const std::vector<retdec::utils::Range<std::uint64_t>>& ranges) : _overlap(overlap), _ranges(ranges)
{
}

/**
 * Return the type of the overlap.
 *
 * @return Type of the overlap.
 */
Overlap OverlapResolver::Result::getOverlap() const
{
	return _overlap;
}

/**
 * Returns the ranges in the result.
 *
 * @return The ranges.
 */
const std::vector<retdec::utils::Range<std::uint64_t>>& OverlapResolver::Result::getRanges() const
{
	return _ranges;
}

/**
 * Resolves overlapping of the two given ranges. The function checks overlap of the second
 * range over the first range. OverlapResolver::Result object is returned containing new ranges
 * that are in ascending order and no longer overlap themselves. This means that first range
 * is cut off or completely cut out.
 *
 * @param first The first range.
 * @param second The second range.
 *
 * @return OverlapResolver::Result object.
 */
OverlapResolver::Result OverlapResolver::resolve(const retdec::utils::Range<std::uint64_t>& first, const retdec::utils::Range<std::uint64_t>& second)
{
	std::int64_t startDiff = first.getStart() - second.getStart();
	std::int64_t endDiff = first.getEnd() - second.getEnd();

	// First, check for full overlap of the first range by the second range
	if ((second.getStart() <= first.getStart() && first.getEnd() <= second.getEnd()) ||
		(startDiff == 0 && first.getEnd() <= second.getEnd()) ||
		(second.getStart() <= first.getStart() && endDiff == 0))
	{
		return Result(Overlap::Full, { second });
	}

	bool startInRange = first.contains(second.getStart());
	bool endInRange = first.contains(second.getEnd());

	// Check whether start of the second range is in the first range but end is not.
	if ((startInRange && !endInRange) || (startInRange && endDiff == 0))
	{
		retdec::utils::Range<std::uint64_t> newRange = retdec::utils::Range<std::uint64_t>(first.getStart(), second.getStart());
		return Result(Overlap::OverEnd, { newRange, second });
	}
	// Check whether end of the second range is in the first range but start is not.
	else if ((!startInRange && endInRange) || (startDiff == 0 && endInRange))
	{
		retdec::utils::Range<std::uint64_t> newRange = retdec::utils::Range<std::uint64_t>(second.getEnd(), first.getEnd());
		return Result(Overlap::OverStart, { second, newRange });
	}
	// Check whether both the start and the end of the second range are in the first range.
	else if (startInRange && endInRange)
	{
		retdec::utils::Range<std::uint64_t> newRange1 = retdec::utils::Range<std::uint64_t>(first.getStart(), second.getStart());
		retdec::utils::Range<std::uint64_t> newRange2 = retdec::utils::Range<std::uint64_t>(second.getEnd(), first.getEnd());
		return Result(Overlap::InMiddle, { newRange1, second, newRange2 });
	}

	// No overlap, but we still need to put them in ascending order.
	std::vector<retdec::utils::Range<std::uint64_t>> defaultRet;
	if (first.getStart() < second.getStart())
		defaultRet = { first, second };
	else
		defaultRet = { second, first };

	return Result(Overlap::None, defaultRet);
}

} // namespace loader
} // namespace retdec
