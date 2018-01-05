/**
* @file include/retdec/utils/container.h
* @brief Container utilities.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_UTILS_CONTAINER_H
#define RETDEC_UTILS_CONTAINER_H

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <iterator>
#include <list>
#include <map>
#include <queue>
#include <set>
#include <stack>
#include <string>
#include <unordered_set>
#include <vector>

#include "retdec/utils/filter_iterator.h"

namespace retdec {
namespace utils {

/// @name General Operations with Containers
/// @{

/**
* @brief Returns @c true if @a container contains @a item, @c false otherwise.
*
* @tparam Container Type of the container.
* @tparam Item Type of the items that @a container holds.
*
* If Container is a map, Item has to be a key. To check whether a map contains
* a value, use mapHasValue<>().
*/
// Note to developers: For sequential containers that don't have the find()
// member function, like std::vector or std::list, add a "specialization" which
// uses std::find() from the <algorithm> header file.
template<class Container, typename Item>
bool hasItem(const Container &container, const Item &item) {
	return container.find(item) != container.end();
}

/**
* @brief A "specialization" of hasItem<>() for std::list.
*/
template<typename Item>
bool hasItem(const std::list<Item> &container, const Item &item) {
	// std::list doesn't have the find() member function.
	return find(container.begin(), container.end(), item) != container.end();
}

/**
* @brief A "specialization" of hasItem<>() for std::vector.
*/
template<typename Item>
bool hasItem(const std::vector<Item> &container, const Item &item) {
	// std::vector doesn't have the find() member function.
	return find(container.begin(), container.end(), item) != container.end();
}

/**
* @brief Returns the n-th item in @a container.
*
* @tparam Item Type of the items that @a container holds.
*
* @par Preconditions
*  - <tt>1 <= n <= container.size()</tt>
*/
template<typename Item>
const Item &getNthItem(const std::vector<Item> &container, std::size_t n) {
	assert(1 <= n && n <= container.size() && "n is out of bounds");

	return container[n - 1];
}

/**
* @brief Returns the n-th item in @a container.
*
* @tparam Item Type of the items that @a container holds.
*
* @par Preconditions
*  - <tt>1 <= n <= container.size()</tt>
*/
template<typename Item>
const Item &getNthItem(const std::list<Item> &container, std::size_t n) {
	assert(1 <= n && n <= container.size() && "n is out of bounds");

	auto itemIt = container.begin();
	std::advance(itemIt, n - 1);
	return *itemIt;
}

/**
* @brief Returns the found value if @a container contains @a item, @a
*        defaultValue otherwise.
*
* @tparam Container Type of the container.
* @tparam Item Type of the items that @a container holds.
*
* If Container is a map, the searched and returned values are pairs. To get a
* value corresponding to a given key from a map, use mapGetValueOrDefault<>().
*/
// Note to developers: For sequential containers that don't have the find()
// member function, like std::vector or std::list, add a "specialization" which
// uses std::find() from the <algorithm> header file.
template<class Container, typename Item>
Item getValueOrDefault(const Container &container, const Item &item,
		Item defaultValue = Item()) {
	auto i = container.find(item);
	return i != container.end() ? *i : defaultValue;
}

/**
* @brief A "specialization" of getValueOrDefault<>() for std::list.
*/
template<typename Item>
Item getValueOrDefault(const std::list<Item> &container,
		const Item &item, Item defaultValue = Item()) {
	// std::list doesn't have the find() member function.
	auto i = std::find(container.begin(), container.end(), item);
	return i != container.end() ? *i : defaultValue;
}

/**
* @brief A "specialization" of getValueOrDefault<>() for std::vector.
*/
template<typename Item>
Item getValueOrDefault(const std::vector<Item> &container,
		const Item &item, Item defaultValue = Item()) {
	// std::vector doesn't have the find() member function.
	auto i = std::find(container.begin(), container.end(), item);
	return i != container.end() ? *i : defaultValue;
}

/**
* @brief Removes all occurrences of the given @a item from the given vector.
*
* @tparam Item Type of the items that the vector holds.
*/
template<typename Item>
void removeItem(std::vector<Item> &v, const Item &item) {
	// std::vector does not provide erase() that takes an item as its argument,
	// so we have to use the following idiom, called "erase-remove".
	v.erase(std::remove(v.begin(), v.end(), item), v.end());
}

/**
* @brief Clears the given container.
*
* @tparam Container Type of the container.
*/
template<class Container>
void clear(Container &container) {
	container.clear();
}

/**
* @brief A "specialization" of clear<>() for std::queue.
*/
template<typename Item>
void clear(std::queue<Item> &q) {
	// std::queue doesn't provide the clear() member function.
	while (!q.empty()) {
		q.pop();
	}
}

/**
* @brief A "specialization" of clear<>() for std::stack.
*/
template<typename Item>
void clear(std::stack<Item> &s) {
	// std::stack doesn't provide the clear() member function.
	while (!s.empty()) {
		s.pop();
	}
}

/**
* @brief Returns @c OutputContainer with items from @a input that satistfy @a
*        predicate.
*
* This function is an implementation of the standard functional @c filter()
* function.
*
* Usage example:
* @code
* auto result = filterTo<std::set<int>>(
*     std::vector<int>{1, 2, 3, 4, 5},
*     [](auto i) { return i % 2 == 0; }
* );
* @endcode
* The type of @c result is @c OutputContainer, i.e. @c std::set<int>.
*/
template<typename OutputContainer, typename InputContainer, typename Predicate>
OutputContainer filterTo(const InputContainer &input, const Predicate &predicate) {
	FilterIterator<typename InputContainer::const_iterator> begin(input, predicate);
	decltype(begin) end(input.end());
	return {begin, end};
}

/**
* @brief Returns @c Container with items from @a input that satistfy @a
*        predicate.
*
* It is a shortcut for <tt>filterTo<Container>(input, predicate)</tt>.
*
* Usage example:
* @code
* auto result = filter(
*     std::vector<int>{1, 2, 3, 4, 5},
*     [](auto i) { return i % 2 == 0; }
* );
* @endcode
* The type of @c result is @c Container, i.e. @c std::vector<int>.
*/
template<typename Container, typename Predicate>
Container filter(const Container &input, const Predicate &predicate) {
	return filterTo<Container>(input, predicate);
}

/// @}

/// @name Operations with Sets
/// @{

/**
* @brief Adds all values from @a from into @a to.
*
* @tparam T Type of elements in the sets.
*/
template<typename T>
void addToSet(const std::set<T> &from, std::set<T> &to) {
	to.insert(from.begin(), from.end());
}

/**
* @brief Returns the set union <tt>s1 \\cup s2</tt>.
*
* In other words, this function returns the set whose elements are in @a s1 or
* in @a s2.
*
* @tparam T Type of elements in the sets.
*/
template<typename T>
std::set<T> setUnion(const std::set<T> &s1, const std::set<T> &s2) {
	std::set<T> result;
	std::set_union(s1.begin(), s1.end(), s2.begin(), s2.end(),
		std::inserter(result, result.end()));
	return result;
}

/**
* @brief Returns the set intersection <tt>s1 \\cap s2</tt>.
*
* In other words, this function returns the set whose elements are in both @a
* s1 and @a s2.
*
* @tparam T Type of elements in the sets.
*/
template<typename T>
std::set<T> setIntersection(const std::set<T> &s1, const std::set<T> &s2) {
	std::set<T> result;
	std::set_intersection(s1.begin(), s1.end(), s2.begin(), s2.end(),
		std::inserter(result, result.end()));
	return result;
}

/**
* @brief Returns the set difference <tt>s1 \\setminus s2</tt>.
*
* In other words, this function returns the set whose elements are in @a s1
* but are not in @a s2.
*
* @tparam T Type of elements in the sets.
*/
template<typename T>
std::set<T> setDifference(const std::set<T> &s1, const std::set<T> &s2) {
	std::set<T> result;
	std::set_difference(s1.begin(), s1.end(), s2.begin(), s2.end(),
		std::inserter(result, result.end()));
	return result;
}

/**
* @brief Removes all values that are in @a toRemove from @a from.
*
* @tparam T Type of elements in the sets.
*/
template<typename T>
void removeFromSet(std::set<T> &from, const std::set<T> &toRemove) {
	// The solution using std::set_difference<> is slightly faster
	// than this manual loop:
	//
	//   for (auto &item : toRemove) {
	//       from.erase(item);
	//   }
	//
	// Timings (containers with 10000000 elements):
	//
	//   T           | std::set_difference | for loop |
	//   ------------|---------------------|----------|
	//   int         | 3.08s               |  4.43s   |
	//   std::string | 3.74s               |  6.87s   |
	//
	from = setDifference(from, toRemove);
}

/**
* @brief Returns @c true if @a s1 is disjoint with @a s2.
*
* @tparam T Type of elements in the sets.
*/
template<typename T>
bool areDisjoint(const std::set<T> &s1, const std::set<T> &s2) {
	// s1 and s2 are disjoint iff s1 \cap s2 = \emptyset
	// (see http://en.wikipedia.org/wiki/Disjoint_set)
	return setIntersection(s1, s2).empty();
}

/**
* @brief Returns @c true if @a s1 and @a s2 have at least one item in common.
*
* @tparam T Type of elements in the sets.
*/
template<typename T>
bool shareSomeItem(const std::set<T> &s1, const std::set<T> &s2) {
	return !areDisjoint(s1, s2);
}

/// @}

/// @name Operations with Maps
/// @{

/**
* @brief Returns all keys in the given map @a m.
*
* @tparam Map Type of the map (<tt>std::map</tt> or
*             <tt>std::unordered_map</tt>).
*/
template<typename Map>
std::set<typename Map::key_type> getKeysFromMap(const Map &m) {
	std::set<typename Map::key_type> keys;
	for (auto &p : m) {
		keys.insert(p.first);
	}
	return keys;
}

/**
* @brief Returns all values in the given map @a m.
*
* @tparam Map Type of the map (<tt>std::map</tt> or
*             <tt>std::unordered_map</tt>).
*/
template<typename Map>
std::set<typename Map::mapped_type> getValuesFromMap(const Map &m) {
	std::set<typename Map::mapped_type> keys;
	for (auto &p : m) {
		keys.insert(p.second);
	}
	return keys;
}

/**
* @brief Returns @c true if the given map @a m has a key @a k, @c false
*        otherwise.
*
* @tparam Map Type of the map (<tt>std::map</tt> or
*             <tt>std::unordered_map</tt>).
*/
template<typename Map>
bool mapHasKey(const Map &m, const typename Map::key_type &k) {
	return m.find(k) != m.end();
}

/**
* @brief Returns @c true if the given map @a m has a value @a v, @c false
*        otherwise.
*
* @tparam Map Type of the map (<tt>std::map</tt> or
*             <tt>std::unordered_map</tt>).
*/
template<typename Map>
bool mapHasValue(const Map &m, const typename Map::mapped_type &v) {
	for (auto &p : m) {
		if (p.second == v) {
			return true;
		}
	}
	return false;
}

/**
* @brief Returns the value associated to the given @a key in @a m, or
*        @a defaultValue if there is no @a key in @a m.
*
* @tparam Map Type of the map (<tt>std::map</tt> or
*             <tt>std::unordered_map</tt>).
*/
template<typename Map>
typename Map::mapped_type mapGetValueOrDefault(
		const Map &m,
		const typename Map::key_type &key,
		typename Map::mapped_type defaultValue = typename Map::mapped_type()) {
	auto i = m.find(key);
	return i != m.end() ? i->second : defaultValue;
}

/**
* @brief Returns the maximum value from @a m.
*
* If @a m is empty, this function returns <tt>Map::mapped_type()</tt>
* (default-constructed value).
*/
template<typename Map>
typename Map::mapped_type mapGetMaxValue(const Map &m) {
	auto max = std::max_element(m.begin(), m.end(),
		[] (const auto &p1, const auto &p2) { return p1.second < p2.second; });
	return max != m.end() ? max->second : typename Map::mapped_type();
}

/**
* @brief Adds the pair <tt><key, value></tt> to map @a m.
*
* @return Reference to the added value.
*
* @tparam Map Type of the map (<tt>std::map</tt> or
*             <tt>std::unordered_map</tt>).
*
* If the key already exists in the map, its value is overwritten.
*
* The behavior of this function is similar to <tt>m[key] = value</tt>, but does
* not require values in the map to have the default constructor. To use @c
* operator[] in a map, values in the map must have a default constructor. If
* this is not the case, you cannot use @c operator[].
*/
template<typename Map>
typename Map::mapped_type &addToMap(
		const typename Map::key_type &key,
		const typename Map::mapped_type &value,
		Map &m) {
	auto i = m.find(key);
	if (i != m.end()) {
		i->second = value;
		return i->second;
	}
	return m.emplace(key, value).first->second;
}

/**
* @brief Returns a new map that has swapped keys and values.
*
* @tparam K Type of objects serving as keys.
* @tparam V Type of objects serving as values.
*
* For example, if you have <tt>std::map<int, std::string></tt>, this function
* returns <tt>std::map<std::string, int></tt>.
*
* You have to ensure that all values in @c m are distinct; otherwise, the
* returned map may have less elements than @c m.
*/
template<typename K, typename V>
std::map<V, K> getMapWithSwappedKeysAndValues(const std::map<K, V> &m) {
	std::map<V, K> result;
	for (const auto &p : m) {
		result.emplace(p.second, p.first);
	}
	return result;
}

/// @}

/// @name Non-iterable Containers
///
/// They let you insert and check for elements as well as remove elements.
/// They will not let you iterate through them or perform anything that could
/// cause nondeterminism arraising from random order of elements in the
/// underlying container.
/// Use them if their operations are sufficient for your initiall purpose but
/// you are affraid that in future they could be used the wrong way and cause
/// nondeterminism.
/// @{

template <class Elem>
class NonIterableSet {
	public:
		NonIterableSet()
		{

		}
		NonIterableSet(std::initializer_list<Elem> il) :
			_data(il)
		{

		}

		void clear() {
			_data.clear();
		}

		std::pair<Elem, bool> insert(const Elem& val) {
			auto p = _data.insert(val);
			return {*p.first, p.second};
		}

		bool has(const Elem& val) const {
			return _data.find(val) != _data.end();
		}

		bool hasNot(const Elem& val) const {
			return _data.find(val) == _data.end();
		}

	protected:
		std::set<Elem> _data;
};

/// @}

/// @name Hash functor for enum class
///
/// This is universal hash functor for enum class that can be
/// used in std::unordered_map with enum class keys. The most
/// recent compilers support this implicitly, but older versions
/// of GCC need explicit hash function for user-defined enum classes.
///
/// Usage:
/// @code
/// enum class Fruit { Apple, Banana, Orange };
///
/// std::unordered_map<Fruit, std::string, EnumClassKeyHash> m;
/// @endcode
///
/// Solution insipred by: http://stackoverflow.com/a/24847480/2534752
/// @{

struct EnumClassKeyHash
{
	template <typename T>
	std::size_t operator()(T t) const
	{
		return static_cast<std::size_t>(t);
	}
};

/// @}

} // namespace utils
} // namespace retdec

#endif
