/**
 * @file include/retdec/utils/range.h
 * @brief Declaration of templated Range class.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_UTILS_RANGE_H
#define RETDEC_UTILS_RANGE_H

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <sstream>
#include <type_traits>
#include <utility>
#include <vector>

namespace retdec {
namespace utils {

class InvalidRangeException : public std::exception
{
public:
	InvalidRangeException() noexcept {}
	InvalidRangeException(const InvalidRangeException&) noexcept = default;
	virtual ~InvalidRangeException() = default;

	virtual const char* what() const noexcept override { return "Invalid Range: end is greater than start"; }
};

/**
 * Range <start, end) -- including start, excluding end.
 *
 * Range class can be used to represent the range defined by two specific
 * values, one starting and one ending value.
 * These values can be of any type, but this type must provide subtraction
 * operator and must have relational operators defined.
 *
 * @tparam Parametrized type of the range.
 */
template <typename T> class Range
{
public:
	using RangeType = T;

	/**
	 * Default constructor.
	 */
	Range() : _start(), _end() {}

	/**
	 * Constructor for specific range.
	 *
	 * @param start The starting value of the range.
	 * @param end The ending value of the range.
	 */
	Range(const RangeType& start, const RangeType& end) : _start(start), _end(end)
	{
		if (end < start)
			throw InvalidRangeException();
	}

	/**
	 * Copy constructor.
	 *
	 * @param range Range to copy.
	 */
	Range(const Range<RangeType>& range) : _start(range._start), _end(range._end) {}

	/**
	 * Move constructor.
	 *
	 * @param range Range to move.
	 */
	Range(Range<RangeType>&& range) noexcept(std::is_nothrow_move_constructible<RangeType>::value)
		: _start(std::move(range._start)), _end(std::move(range._end)) {}

	/**
	 * Destructor.
	 */
	virtual ~Range() {}

	/**
	 * Assign operator.
	 *
	 * @param rhs Right-hand side of the assignment.
	 *
	 * @return Assigned object.
	 */
	Range& operator =(const Range<RangeType>& rhs) = default;

	/**
	 * Move-assign operator.
	 *
	 * @param rhs Right-hand side of the assignment.
	 *
	 * @return Assigned object.
	 */
	Range& operator =(Range<RangeType>&& rhs) = default;

	/**
	 * Returns the starting value of the range.
	 *
	 * @return Starting value of the range.
	 */
	const RangeType& getStart() const { return _start; }

	/**
	 * Returns the ending value of the range.
	 *
	 * @return Ending value of the range.
	 */
	const RangeType& getEnd() const { return _end; }

	/**
	 * Sets the starting value of the range.
	 *
	 * @param start The starting value of the range.
	 */
	void setStart(const RangeType& start)
	{
		if (_end < start)
			throw InvalidRangeException();
		_start = start;
	}

	/**
	 * Sets the ending value of the range.
	 *
	 * @param end The ending value of the range.
	 */
	void setEnd(const RangeType& end)
	{
		if (end < _start)
			throw InvalidRangeException();
		_end = end;
	}

	/**
	 * Sets the starting value of the range.
	 *
	 * @param start The starting value of the range.
	 * @param end   The ending value of the range.
	 */
	void setStartEnd(const RangeType& start, const RangeType& end)
	{
		if (end < start)
			throw InvalidRangeException();
		_start = start;
		_end = end;
	}

	/**
	 * Returns the size of the range.
	 *
	 * @return Size of the range.
	 */
	RangeType getSize() const { return _end - _start; }

	/**
	 * Checks whether range contains given value. It checks for non-strict order.
	 *
	 * @param value Value to check.
	 *
	 * @return True if in range, otherwise false.
	 */
	bool contains(const RangeType& value) const { return _start <= value && value < _end; }

	/**
	 * Checks whether range fully contains given range, i.e. it contains both
	 * its start and end.
	 *
	 * @param o Range to check.
	 *
	 * @return True if in range, otherwise false.
	 */
	bool contains(const Range<RangeType>& o) const { return contains(o.getStart()) && o.getEnd() <= getEnd(); }

	/**
	 * Check whether range overlaps with the given range, i.e. there exists
	 * some value that which is in both ranges.
	 */
	bool overlaps(const Range<RangeType>& o) const { return _start < o._end && o._start < _end; }

	/**
	 * Return whether two ranges are equal. They are equal if their starting
	 * and ending values are the same.
	 *
	 * @return True if equal, otherwise false.
	 */
	bool operator ==(const Range<RangeType>& rhs) const { return _start == rhs._start && _end == rhs._end; }

	/**
	 * Return whether two ranges are not equal. They are equal if their starting
	 * and ending values are the same.
	 *
	 * @return True if not equal, otherwise false.
	 */
	bool operator !=(const Range<RangeType>& rhs) const { return !(*this == rhs); }

	friend std::ostream& operator<<(
			std::ostream& out,
			const Range<RangeType>& r)
	{
		return out << std::hex << std::showbase << "<" << r.getStart() << ", " << r.getEnd() << ")";
	}

protected:
	RangeType _start, _end;
};

/**
 * Range container provides storing multiple ranges
 * in one container while keeping the ranges disjoint.
 * This container also looks for continuous ranges and
 * merges them together into one range. All ranges are kept
 * in ascending order.
 *
 * @tparam T Range element type.
 */
template <typename T, typename = std::enable_if_t<std::is_integral<T>::value, void>> class RangeContainer
{
public:
	using iterator = typename std::vector<T>::iterator;
	using const_iterator = typename std::vector<T>::const_iterator;
	using RangeType = Range<T>;
	using RangeElementType = T;

	RangeContainer() = default;
	RangeContainer(const RangeContainer&) = default;
	RangeContainer(RangeContainer&&) = default;

	RangeContainer& operator=(const RangeContainer&) = default;
	RangeContainer& operator=(RangeContainer&&) = default;

	auto begin() { return _ranges.begin(); }
	auto end() { return _ranges.end(); }
	auto begin() const { return _ranges.begin(); }
	auto end() const { return _ranges.end(); }
	std::size_t size() const { return _ranges.size(); }
	bool empty() const { return _ranges.empty(); }
	void clear() { _ranges.clear(); }

	decltype(auto) operator[](std::size_t index) { return _ranges[index]; }
	decltype(auto) operator[](std::size_t index) const { return _ranges[index]; }

	/**
	 * Adds new range into the container. Range is merged with other ranges if it overlaps
	 * it or is continuous with it. This method invalidates iterators.
	 *
	 * @tparam RangeT Range type.
	 * @param range Range to insert.
	 */
	template <typename RangeT>
	void addRange(RangeT&& range)
	{
		// Find the range which ends right before the inserted range.
		auto startItr = std::lower_bound(_ranges.begin(), _ranges.end(), range.getStart(),
				[](const auto& range, const auto& start) {
					return range.getEnd() < start;
				});
		// Find the range which starts right after the inserted range.
		auto endItr = std::upper_bound(_ranges.begin(), _ranges.end(), range.getEnd(),
				[](const auto& end, const auto& range) {
					return end < range.getStart();
				});

		// If the lower and upper bound are the same, that means we have unique
		// range which does not overlap any other range.
		// Just insert it into the right position.
		if (startItr == endItr)
		{
			_ranges.insert(startItr, std::forward<RangeT>(range));
		}
		else
		{
			// Rewrite the lower bound and remove the rest which overlaps our
			// inserted range.
			*startItr = RangeType{
					std::min(range.getStart(), startItr->getStart()),
					std::max(range.getEnd(), (endItr - 1)->getEnd())
				};
			if (startItr + 1 != endItr)
				_ranges.erase(startItr + 1, endItr);
		}
	}

private:
	std::vector<RangeType> _ranges;
};

} // namespace utils
} // namespace retdec

#endif
