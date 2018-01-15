/**
* @file include/retdec/utils/filter_iterator.h
* @brief An adapter of an iterator range in which some elements of the range
*        are skipped.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_UTILS_FILTER_ITERATOR_H
#define RETDEC_UTILS_FILTER_ITERATOR_H

#include <functional>
#include <iterator>
#include <utility>

namespace retdec {
namespace utils {

/**
* @brief An adapter of an iterator range in which some elements of the range
*        are skipped.
*
* The filter iterator adapter creates a view of an iterator range in which some
* elements of the range are skipped. A predicate function object controls which
* elements are skipped. When the predicate is applied to an element, if it
* returns true, then the element is retained, and if it returns false, then the
* element is skipped over. When skipping over elements, it is necessary for the
* filter adapter to know when to stop so as to avoid going past the end of the
* underlying range. A filter iterator is, therefore, constructed with pair of
* iterators indicating the range of elements in the unfiltered sequence to be
* traversed and a predicate.
*
* Based on filter_iterator from Boost
* (http://www.boost.org/doc/libs/master/libs/iterator/doc/filter_iterator.html).
* See it for more information. Note, however, that our interface differs from
* the one provided by Boost.
*
* @tparam Iterator Type of the iterators in the range.
*/
template<typename Iterator>
class FilterIterator {
public:
	// Standard typedefs.
	using value_type = typename std::iterator_traits<Iterator>::value_type;
	using reference = typename std::iterator_traits<Iterator>::reference;
	using pointer = typename std::iterator_traits<Iterator>::pointer;
	using difference_type = typename std::iterator_traits<Iterator>::difference_type;
	using iterator_category = std::forward_iterator_tag;

public:
	/**
	* @brief Creates an iterator over the given range.
	*
	* @param[in] begin Start of the range.
	* @param[in] end End of the range.
	* @param[in] predicate Predicate for determining which elements should be
	*                      retained.
	*/
	template<typename Predicate>
	FilterIterator(Iterator begin, Iterator end, Predicate &&predicate):
			current(std::move(begin)),
			end(std::move(end)),
			predicate(std::forward<Predicate>(predicate)) {
		skipElementsWhilePredicateIsFalse();
	}

	/**
	* @brief Creates an iterator over the given container.
	*
	* @param[in] container Container to be iterated.
	* @param[in] predicate Predicate for determining which elements should be
	*                      retained.
	*
	* This constructor is a handy alias for the following code:
	* @code
	* FilterIterator(container.begin(), container.end(), predicate)
	* @endcode
	*/
	template<typename Container, typename Predicate>
	FilterIterator(Container &container, Predicate &&predicate):
		FilterIterator(std::begin(container), std::end(container),
			std::forward<Predicate>(predicate)) {}

	/**
	* @brief Creates an end iterator.
	*/
	FilterIterator(Iterator end): current(end), end(std::move(end)) {}

	FilterIterator(const FilterIterator &other) = default;

	FilterIterator(FilterIterator &&other) = default;

	~FilterIterator() = default;

	FilterIterator &operator=(const FilterIterator &other) = default;

	reference operator*() const {
		return *current;
	}

	pointer operator->() const {
		return &*current;
	}

	bool operator==(const FilterIterator &other) const {
		return current == other.current;
	}

	bool operator!=(const FilterIterator &other) const {
		return !(*this == other);
	}

	FilterIterator &operator++() {
		++current;
		skipElementsWhilePredicateIsFalse();
		return *this;
	}

private:
	void skipElementsWhilePredicateIsFalse() {
		while (current != end && !predicate(*current)) {
			++current;
		}
	}

private:
	Iterator current;
	Iterator end;
	std::function<bool (reference)> predicate;
};

} // namespace utils
} // namespace retdec

#endif
