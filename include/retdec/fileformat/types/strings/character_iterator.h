/**
 * @file include/retdec/fileformat/types/strings/character_iterator.h
 * @brief Class for character iterator.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_FILEFORMAT_TYPES_STRINGS_CHARACTER_ITERATOR_H
#define RETDEC_FILEFORMAT_TYPES_STRINGS_CHARACTER_ITERATOR_H

#include <cctype>
#include <iterator>

namespace retdec {
namespace fileformat {

enum class CharacterEndianness
{
	Little,
	Big
};

/**
 * Represents iterator for string characters in the random access container.
 * It supports different character sizes and performs boundary checks.
 */
template <typename It, typename = std::enable_if_t<std::is_same<typename std::iterator_traits<It>::iterator_category, std::random_access_iterator_tag>::value>>
class CharacterIterator
{
	private:
		It itr, first, last;
		std::size_t charStep;

		/**
		 * Advances iterator forwards or backwards with checking of boundaries.
		 *
		 * @param n Number of elements to advance.
		 *
		 * @return Original iterator before advancing.
		 */
		It safeAdvance(std::ptrdiff_t n)
		{
			std::ptrdiff_t direction = n < 0 ? -1 : 1;
			It end = direction == 1 ? last : first;
			n = std::abs(n);

			auto orig = itr;

			// Advance N times
			for (std::ptrdiff_t advIdx = 0; advIdx < n; ++advIdx)
			{
				// Use `charStep` long advance steps
				for (std::size_t i = 0; i < charStep; ++i, std::advance(itr, direction))
				{
					if (itr == end)
						return orig;
				}
			}

			return orig;
		}

		bool pointsToValidCharacter(const It& charByte, const It& paddingFirst, const It& paddingLast) const
		{
			bool result = std::isprint(static_cast<unsigned char>(*charByte));

			for (auto itr = paddingFirst; result && itr != paddingLast; ++itr)
				result = (*itr == '\0');

			return result;
		}

	public:
		CharacterIterator(It first, It last, std::size_t charStep) : itr(first), first(first), last(last), charStep(charStep) {}
		CharacterIterator(It itr, It first, It last, std::size_t charStep) : itr(itr), first(first), last(last), charStep(charStep) {}
		CharacterIterator(const CharacterIterator&) = default;

		CharacterIterator& operator=(const CharacterIterator&) = default;

		/**
		 * Dereference operator.
		 *
		 * @return Pointed element.
		 */
		char operator*() const
		{
			return static_cast<char>(*itr);
		}

		/**
		 * Makes the iterator point to the next character. Does nothing if iterator would cross the end.
		 *
		 * @return Incremented iterator.
		 */
		CharacterIterator& operator++()
		{
			safeAdvance(1);
			return *this;
		}

		/**
		 * Makes the iterator point to the next character. Does nothing if iterator would cross the end.
		 *
		 * @return Original iterator before incrementation.
		 */
		CharacterIterator operator++(int)
		{
			auto tmp = *this;
			safeAdvance(1);
			return tmp;
		}

		/**
		 * Makes the iterator point to the previous character. Does nothing if iterator would cross the beginning.
		 *
		 * @return Decremented iterator.
		 */
		CharacterIterator& operator--()
		{
			safeAdvance(-1);
			return *this;
		}

		/**
		 * Makes the iterator point to the previous character. Does nothing if iterator would cross the beginning.
		 *
		 * @return Original iterator before decrementation.
		 */
		CharacterIterator operator--(int)
		{
			auto tmp = *this;
			safeAdvance(-1);
			return tmp;
		}

		/**
		 * Moves iterator forwards by the specified amount of characters. Does not cross the end or beginning of the data.
		 *
		 * @return Moved iterator.
		 */
		CharacterIterator& operator+=(std::ptrdiff_t diff)
		{
			safeAdvance(diff);
			return *this;
		}

		/**
		 * Moves iterator backwards by the specified amount of characters. Does not cross the end or beginning of the data.
		 *
		 * @return Moved iterator.
		 */
		CharacterIterator& operator-=(std::ptrdiff_t diff)
		{
			safeAdvance(-diff);
			return *this;
		}

		/**
		 * Moves iterator forwards by the specified amount of characters. Does not cross the end or beginning of the data.
		 *
		 * @return Moved iterator.
		 */
		CharacterIterator operator+(std::ptrdiff_t diff) const
		{
			auto tmp = *this;
			tmp.safeAdvance(diff);
			return tmp;
		}

		/**
		 * Moves iterator backwards by the specified amount of characters. Does not cross the end or beginning of the data.
		 *
		 * @return Moved iterator.
		 */
		CharacterIterator operator-(std::ptrdiff_t diff) const
		{
			auto tmp = *this;
			tmp.safeAdvance(-diff);
			return tmp;
		}

		/**
		 * Returns the distance (in number of characters) between two iterators.
		 *
		 * @return Distance.
		 */
		std::ptrdiff_t operator-(const CharacterIterator& rhs) const
		{
			// We need to return 0 only if iterators are the same
			if (itr == rhs.itr)
				return 0;

			// If `charStep` is greater than 1 we are in risk that the size of data is not going to be congruent to `charStep`.
			// If the difference between iterators is going to be 0, it means this happened.
			// We need to return 1 because it you take `end - itr`, where `itr` is iterator somewhere near the end (with the real distance less than `charStep`),
			// you still need to be able to do `itr + (end - itr)` and end up with the `end`.
			// If this return 0, you would end up at `itr`, which is `end - 1`.
			std::ptrdiff_t diff = (itr - rhs.itr) / charStep;
			return diff == 0 ? 1 : diff;
		}

		/**
		 * Checks whether iterators are equal. They are equal if and only if they point to the same element.
		 *
		 * @return `true` if equal, otherwise `false`.
		 */
		bool operator==(const CharacterIterator& rhs) const
		{
			return itr == rhs.itr;
		}

		/**
		 * Checks whether iterators are not equal. They are equal if and only if they point to the same element.
		 *
		 * @return `true` if not equal, otherwise `false`.
		 */
		bool operator!=(const CharacterIterator& rhs) const
		{
			return !(*this == rhs);
		}

		/**
		 * Checks whether one iterator is less than the other.
		 *
		 * @return `true` if it is less, otherwise `false`.
		 */
		bool operator<(const CharacterIterator& rhs) const
		{
			return itr < rhs.itr;
		}

		/**
		 * Returns the underlying iterator of the byte sequence.
		 *
		 * @return Underlying iterator.
		 */
		const It& getUnderlyingIterator() const
		{
			return itr;
		}

		/**
		 * Checks whether the iterator points to a valid character. Character is valid if the underlying iterator points to a byte
		 * which is printable with respect to the provided endianness. In case of `charStep` being greater than 1, the remaining bytes
		 * must be zero. If iterator points to an end, this function always returns `false`.
		 *
		 * @return `true` if points to valid character, otherwise `false`.
		 */
		bool pointsToValidCharacter(CharacterEndianness endian) const
		{
			if (itr == last)
				return false;

			if (endian == CharacterEndianness::Little)
				return pointsToValidCharacter(itr, itr + 1, itr + charStep);
			else if (endian == CharacterEndianness::Big)
				return pointsToValidCharacter(itr + charStep - 1, itr, itr + charStep - 1);
			else
				return false;
		}
};

/**
 * Creates character iterator pointing to the beginning of the sequence.
 *
 * @param first Lower bound.
 * @param last Upper bound.
 * @param charStep Size of the single character.
 *
 * @return Character iterator.
 */
template <typename It>
CharacterIterator<It> makeCharacterIterator(It first, It last, std::size_t charStep)
{
	return { first, last, charStep };
}

/**
 * Creates character iterator pointing to the specific element of the sequence.
 *
 * @param itr Iterator of element which to point at.
 * @param first Lower bound.
 * @param last Upper bound.
 * @param charStep Size of the single character.
 *
 * @return Character iterator.
 */
template <typename It>
CharacterIterator<It> makeCharacterIterator(It itr, It first, It last, std::size_t charStep)
{
	return { itr, first, last, charStep };
}

} // namespace fileformat
} // namespace retdec

namespace std {

template <typename It>
struct iterator_traits<retdec::fileformat::CharacterIterator<It>>
{
	using difference_type = std::ptrdiff_t;
	using value_type = char;
	using iterator_category = std::random_access_iterator_tag;
};

}

#endif
