/**
* @file include/retdec/llvmir2hll/support/caching.h
* @brief A mixin for enabling caching of computed results.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SUPPORT_CACHING_H
#define RETDEC_LLVMIR2HLL_SUPPORT_CACHING_H

#include <unordered_map>

namespace retdec {
namespace llvmir2hll {

/**
* @brief A mixin for enabling caching of computed results.
*
* @tparam CachedKey Key with which a value is associated.
* @tparam CachedValue Value that is associated with a key.
* @tparam HashFunc Hashing function for CachedKey. The default is @c
*                  std::hash<CachedKey>.
*
* Usage example (see Analysis/UsedVarsVisitor):
* @code
* class UsedVarsVisitor: public Caching<ShPtr<Value>, ShPtr<UsedVars>,
*         HashFuncShPtr<Value>> {
*     UsedVarsVisitor::UsedVarsVisitor(bool enableCaching):
*         Caching(enableCaching) {}
*
*    // ...
* };
*
* ShPtr<UsedVars> UsedVarsVisitor::getUsedVars(ShPtr<Value> value) {
*    // Caching.
*    ShPtr<UsedVars> usedVars;
*    if (getCachedResult(value, usedVars)) {
*        return usedVars;
*    }
*
*    // The result is not cached, so compute it.
*
*    // Caching.
*    addToCache(value, usedVars);
*
*    return usedVars;
* }
* @endcode
*/
template<typename CachedKey, typename CachedValue,
	typename HashFunc = std::hash<CachedKey>>
class Caching {
public:
	explicit Caching(bool enableCaching): cachingEnabled(enableCaching) {}

	/**
	* @brief Enables caching.
	*
	* It also clears the cache of the already cached results.
	*/
	void enableCaching() {
		cachingEnabled = true;
		clearCache();
	}

	/**
	* @brief Disables caching.
	*
	* It also clears the cache of the already cached results.
	*/
	void disableCaching() {
		cachingEnabled = false;
		clearCache();
	}

	/**
	* @brief Clears the cache of the already cached results.
	*/
	void clearCache() {
		cache.clear();
	}

	/**
	* @brief Removes the value corresponding to the given key from the cache.
	*
	* The key is removed as well. If there is no value corresponding to @a key,
	* this function does nothing.
	*/
	void removeFromCache(const CachedKey &key) {
		cache.erase(key);
	}

	/**
	* @brief Returns @c true if caching is enabled, @c false otherwise.
	*/
	bool isCachingEnabled() const {
		return cachingEnabled;
	}

protected:
	/**
	* @brief If caching is enabled, associates the given @a value with @a key.
	*/
	void addToCache(const CachedKey &key, const CachedValue &value) {
		if (cachingEnabled) {
			cache[key] = value;
		}
	}

	/**
	* @brief If caching is enabled, stores the value associated with @a key
	*        into @a value.
	*
	* @return @c true if there is a value associated to @a key, @c false otherwise.
	*
	* If there is a value associated with @a key, the value of @a value is left
	* unchanged.
	*/
	bool getCachedResult(const CachedKey &key, CachedValue &value) const {
		if (cachingEnabled) {
			auto it = cache.find(key);
			if (it != cache.end()) {
				value = it->second;
				return true;
			}
		}
		return false;
	}

private:
	/// Container for storing cached results.
	// For performance reasons, it is better to use an unordered_map (i.e. a
	// hash table) instead of a sorted map (i.e. std::map). The reason is that
	// a std::map can retrieve a value associated to a key in O(log(n)), where
	// n is the number of items in the map, while an unordered_map can do this
	// in O(1). Insertions into the maps have the same complexities.
	using Cache = std::unordered_map<CachedKey, CachedValue, HashFunc>;

private:
	/// Is caching enabled?
	bool cachingEnabled;

	/// Cache for storing cached results.
	Cache cache;
};

} // namespace llvmir2hll
} // namespace retdec

#endif
