/**
 * @file include/retdec/utils/filesystem_path.h
 * @brief FilesystemPath class implementation for unified work with filepaths.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_UTILS_FILESYSTEM_PATH_H
#define RETDEC_UTILS_FILESYSTEM_PATH_H

#include <algorithm>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "retdec/utils/os.h"
#include "retdec/utils/string.h"

namespace retdec {
namespace utils {

class FilesystemPathImpl;

/**
 * @brief Abstraction of a filesystem path and its subpaths.
 *
 * FilesystemPath represents a path in a user filesystem. It also
 * supports iterating over the subpaths in the specified path.
 * Loading of subpaths is performed through lazy loading. Subpaths are
 * loaded only if they are requested through begin() or end() call.
 */
class FilesystemPath
{
public:
	FilesystemPath() = delete;
	FilesystemPath(const std::string& path);
	FilesystemPath(const FilesystemPath& fspath);
	~FilesystemPath();

	std::string getPath() const;
	std::string getParentPath() const;
	std::string getAbsolutePath() const;
	bool exists() const;
	bool isDirectory() const;
	bool isFile() const;
	bool isAbsolute() const;
	bool isRelative() const;

	void append(const std::string& path);

	/**
	 * Iterator represent the node for subpath traversing.
	 */
	template <
		typename Category,
		typename Type,
		typename Reference = Type&,
		typename Pointer = Type*,
		typename Distance = std::ptrdiff_t
	>
	class iterator_impl
	{
	public:
		using difference_type = Distance;
		using value_type = Type;
		using reference = Reference;
		using pointer = Pointer;
		using iterator_category = Category;

		iterator_impl(const FilesystemPath* root, std::uint64_t index = 0) : _root(root), _index(index) {} ///< Constructor.

		iterator_impl() = default;
		iterator_impl(const iterator_impl& itr) = default;

		/**
		 * Assignment operator.
		 *
		 * @param rhs Right-hand side of the expression.
		 *
		 * @return Copied right-hand side assigned to iterator.
		 */
		iterator_impl& operator=(const iterator_impl& rhs)
		{
			_root = rhs._root;
			_index = rhs._index;
			return *this;
		}

		/**
		 * Move iterator to the next element. Prefix increment.
		 *
		 * @return The same iterator, while poiting to the next element.
		 */
		iterator_impl& operator++()
		{
			++_index;
			return *this;
		}

		/**
		 * Move iterator to the next element. Postfix increment.
		 *
		 * @return The iterator poiniting to the old element.
		 */
		iterator_impl operator++(int)
		{
			iterator_impl tmp(*this);
			++_index;
			return tmp;
		}

		/**
		 * Compres two iterators. Two iterators are same if they have the same root
		 * and they are pointing to the same element in the subpaths.
		 *
		 * @return True if iterators are same, otherwise false.
		 */
		bool operator==(const iterator_impl& rhs) const
		{
			return ((_root == rhs._root) && (_index == rhs._index));
		}

		/**
		 * Compres two iterators. Two iterators are same if they have the same root
		 * and they are pointing to the same element in the subpaths.
		 *
		 * @return True if iterators are not same, otherwise false.
		 */
		bool operator!=(const iterator_impl& rhs) const
		{
			return !(*this == rhs);
		}

		/**
		 * Access to the FilesystemPath pointed by iterator.
		 *
		 * @return FilesystemPath object.
		 */
		value_type operator*() const
		{
			return _root->_subpaths[_index].get();
		}

		/**
		 * Access to the FilesystemPath pointed by iterator.
		 *
		 * @return FilesystemPath object.
		 */
		value_type operator->() const
		{
			return _root->_subpaths[_index].get();
		}

	private:
		const FilesystemPath* _root; ///< Root path of the iterator.
		std::uint64_t _index; ///< Index of the subpaths in the root path.
	};

	using iterator = iterator_impl<std::input_iterator_tag, FilesystemPath*>;
	using const_iterator = iterator_impl<std::input_iterator_tag, const FilesystemPath*>;

	iterator begin();
	iterator end();
	const_iterator begin() const;
	const_iterator end() const;

	static char separator();

private:
	void loadSubpaths() const;

	std::unique_ptr<FilesystemPathImpl> _impl; ///< Platform specific implementations.

	mutable bool _subpathsLoaded; ///< Internal status for lazy loading.
	mutable std::vector<std::unique_ptr<FilesystemPath>> _subpaths; ///< Subpaths in the specified path.
};

} // namespace utils
} // namespace retdec

#endif
