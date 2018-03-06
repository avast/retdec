/**
 * @file src/utils/filesystem_path.cpp
 * @brief FilesystemPath class implementation for unified work with filepaths.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <string>
#include <iterator>

#include "retdec/utils/filesystem_path.h"
#include "retdec/utils/os.h"
#include "retdec/utils/scope_exit.h"
#include "retdec/utils/string.h"
#include "retdec/utils/value.h"

#ifdef OS_WINDOWS
	#include <windows.h>
	#include <shlwapi.h>
#else
	#include <sys/types.h>
	#include <dirent.h>
	#include <sys/stat.h>
	#include <libgen.h>
#endif

namespace retdec {
namespace utils {

class FilesystemPathImpl
{
public:
	FilesystemPathImpl(const std::string& path) : _path()
	{
		changePath(path);
	}

	FilesystemPathImpl(const FilesystemPathImpl& rhs) : _path(rhs._path) {}
	virtual ~FilesystemPathImpl() = default;

	/**
	 * Returns the path.
	 *
	 * @return Path.
	 */
	const std::string& getPath() const
	{
		return _path;
	}

	/**
	 * Changes the path to the new path. All '/' in the path are replaced
	 * with the system specific path separator. Separator present at the end
	 * of the path (in case of directories) is removed.
	 *
	 * @param path Path to change.
	 */
	void changePath(std::string path)
	{
		std::replace(path.begin(), path.end(), '/', pathSeparator);
		_path = endsWith(path, pathSeparator) ? path.substr(0, path.length() - 1) : path;
	}

	virtual std::string getAbsolutePath() = 0;
	virtual std::string getParentPath() = 0;
	virtual bool subpathsInDirectory(std::vector<std::string>& subpaths) = 0;
	virtual bool exists() = 0;
	virtual bool isFile() = 0;
	virtual bool isDirectory() = 0;
	virtual bool isAbsolute() = 0;

	static char pathSeparator;

protected:
	std::string _path;
};

#ifdef OS_WINDOWS
char FilesystemPathImpl::pathSeparator = '\\';

class FilesystemPathImplWindows : public FilesystemPathImpl
{
public:
	FilesystemPathImplWindows(const std::string& path) : FilesystemPathImpl(path) {}
	FilesystemPathImplWindows(const FilesystemPathImplWindows& rhs) : FilesystemPathImpl(rhs) {}

	virtual std::string getAbsolutePath() override
	{
		char absolutePath[MAX_PATH] = { '\0' };
		if (GetFullPathName(_path.c_str(), MAX_PATH, absolutePath, nullptr) == 0)
			return {};

		return absolutePath;
	}

	virtual std::string getParentPath() override
	{
		// PathRemoveFileSpec() supports only MAX_PATH long paths and modify its parameter
		char parentPathStr[MAX_PATH] = { '\0' };
		strncpy(parentPathStr, _path.c_str(), MAX_PATH - 1);

		PathRemoveFileSpec(parentPathStr);
		return parentPathStr;
	}

	virtual bool subpathsInDirectory(std::vector<std::string>& subpaths) override
	{
		using namespace std::string_literals;

		WIN32_FIND_DATA ffd;

		// We need to add wildcard to examine the content of the directory
		std::string examineDir = _path;
		examineDir.append(pathSeparator + "*"s);

		subpaths.clear();
		HANDLE hFnd = FindFirstFile(examineDir.c_str(), &ffd);
		if (hFnd == reinterpret_cast<HANDLE>(-1))
			return false;

		do
		{
			// skip these 2 special links
			// "." is just link to the current directory
			// ".." is link to the parent directory
			if (strcmp(ffd.cFileName, ".") == 0 || strcmp(ffd.cFileName, "..") == 0)
				continue;

			std::string newPath(_path);
			newPath += pathSeparator;
			newPath.append(ffd.cFileName);
			subpaths.emplace_back(newPath);
		} while (FindNextFile(hFnd, &ffd));

		return true;
	}

	virtual bool exists() override
	{
		return PathFileExists(_path.c_str());
	}

	virtual bool isFile() override
	{
		return !isDirectory();
	}

	virtual bool isDirectory() override
	{
		WIN32_FIND_DATA ffd;
		if (FindFirstFile(_path.c_str(), &ffd) == reinterpret_cast<HANDLE>(-1))
			return false;

		return ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY;
	}

	virtual bool isAbsolute() override
	{
		return !PathIsRelative(_path.c_str());
	}
};
#else
char FilesystemPathImpl::pathSeparator = '/';

class FilesystemPathImplUnix : public FilesystemPathImpl
{
public:
	FilesystemPathImplUnix(const std::string& path) : FilesystemPathImpl(path) {}
	FilesystemPathImplUnix(const FilesystemPathImplUnix& rhs) : FilesystemPathImpl(rhs) {}

	virtual std::string getAbsolutePath() override
	{
#ifdef PATH_MAX
		char absolutePath[PATH_MAX] = { '\0' };
		if (realpath(_path.c_str(), absolutePath) == nullptr)
			return {};
#else
		char* absolutePathStr = realpath(_path.c_str(), nullptr);
		SCOPE_EXIT {
			free(absolutePathStr);
		};
		std::string absolutePath = absolutePathStr;
#endif

		return absolutePath;
	}

	virtual std::string getParentPath() override
	{
		// dirname() can modify the path provided in parameter, so we need to make copy
		char* copyPathStr = new char[_path.length() + 1];
		SCOPE_EXIT {
			delete[] copyPathStr;
		};
		strcpy(copyPathStr, _path.c_str());

		// get the parent directory by calling dirname()
		return dirname(copyPathStr);
	}

	virtual bool subpathsInDirectory(std::vector<std::string>& subpaths) override
	{
		subpaths.clear();
		DIR* dir = opendir(_path.c_str());
		if (dir == nullptr)
			return false;

		dirent* node;
		while ((node = readdir(dir)) != nullptr)
		{
			// skip these 2 special links
			// "." is just link to the current directory
			// ".." is link to the parent directory
			if (strcmp(node->d_name, ".") == 0 || strcmp(node->d_name, "..") == 0)
				continue;

			std::string newPath(_path);
			newPath += pathSeparator;
			newPath.append(node->d_name);
			subpaths.emplace_back(newPath);
		}
		closedir(dir);

		return true;
	}

	virtual bool exists() override
	{
		struct stat st;
		return stat(_path.c_str(), &st) == 0;
	}

	virtual bool isFile() override
	{
		return !isDirectory();
	}

	virtual bool isDirectory() override
	{
		struct stat st;
		if (stat(_path.c_str(), &st) != 0)
			return false;

		return S_ISDIR(st.st_mode);
	}

	virtual bool isAbsolute() override
	{
		return startsWith(_path, pathSeparator);
	}
};
#endif

/**
 * Constructor.
 *
 * @param path The path of the node in the filesystem.
 */
FilesystemPath::FilesystemPath(const std::string& path) : _impl(nullptr), _subpathsLoaded(false), _subpaths()
{
#ifdef OS_WINDOWS
	_impl = std::make_unique<FilesystemPathImplWindows>(path);
#else
	_impl = std::make_unique<FilesystemPathImplUnix>(path);
#endif
}

/**
 * Copy constructor.
 *
 * @param fspath FilesystemPath object to copy.
 */
FilesystemPath::FilesystemPath(const FilesystemPath& fspath) : FilesystemPath(fspath.getPath())
{
}

/**
 * Destructor.
 */
FilesystemPath::~FilesystemPath()
{
}

/**
 * Returns the path in the normalized textual representation
 * (which always contains separator at end of path).
 *
 * @return The path of the node in normalized representation.
 */
std::string FilesystemPath::getPath() const
{
	return _impl->getPath();
}

/**
 * Returns the path to the parent directory of this path in textual representation.
 *
 * @return Parent path.
 */
std::string FilesystemPath::getParentPath() const
{
	return _impl->getParentPath();
}

/**
 * Returns the absolute path.
 *
 * @return Absolute path.
 */
std::string FilesystemPath::getAbsolutePath() const
{
	return _impl->getAbsolutePath();
}

/**
 * Returns the @ref iterator pointing to the first subpath. Performs lazy loading.
 *
 * @return The pointer to the first subpath.
 */
FilesystemPath::iterator FilesystemPath::begin()
{
	if (!_subpathsLoaded)
		loadSubpaths();

	return iterator(this);
}

/**
 * Returns the @ref iterator pointing to the last subpath. Performs lazy loading.
 *
 * @return The pointer to the last subpath.
 */
FilesystemPath::iterator FilesystemPath::end()
{
	if (!_subpathsLoaded)
		loadSubpaths();

	return iterator(this, _subpaths.size());
}

/**
 * Returns the @ref iterator pointing to the first subpath. Performs lazy loading.
 *
 * @return The pointer to the first subpath.
 */
FilesystemPath::const_iterator FilesystemPath::begin() const
{
	if (!_subpathsLoaded)
		loadSubpaths();

	return const_iterator(this);
}

/**
 * Returns the @ref iterator pointing to the last subpath. Performs lazy loading.
 *
 * @return The pointer to the last subpath.
 */
FilesystemPath::const_iterator FilesystemPath::end() const
{
	if (!_subpathsLoaded)
		loadSubpaths();

	return const_iterator(this, _subpaths.size());
}

/**
 * Returns whether the path refers to an existing file or directory.
 *
 * @return @c true if exists, otherwise @c false.
 */
bool FilesystemPath::exists() const
{
	return _impl->exists();
}

/**
 * Checks whether the path is directory or not. The path doesn't have to be loaded.
 *
 * @return True if the path is directory, otherwise false.
 */
bool FilesystemPath::isDirectory() const
{
	return _impl->isDirectory();
}

/**
 * Check whether the path is file or not. The path doesn't have to be loaded.
 *
 * @return True if the path is file, otherwise false.
 */
bool FilesystemPath::isFile() const
{
	return _impl->isFile();
}

/**
 * Check whether the path is absolute or not. The path doesn't have to be loaded.
 *
 * @return True if the path is absolute, otherwise false.
 */
bool FilesystemPath::isAbsolute() const
{
	return _impl->isAbsolute();
}

/**
 * Check whether the path is relative or not. The path doesn't have to be loaded.
 *
 * @return True if the path is relative, otherwise false.
 */
bool FilesystemPath::isRelative() const
{
	return !_impl->isAbsolute();
}

/**
 * Appends the path to the current path with correct separator.
 *
 * @param path Path to append.
 */
void FilesystemPath::append(const std::string& path)
{
	_impl->changePath(getPath() + separator() + path);
	_subpathsLoaded = false;
}

/**
 * Returns the path component separator used on the specific system.
 *
 * @return Path separator.
 */
char FilesystemPath::separator()
{
	return FilesystemPathImpl::pathSeparator;
}

/**
 * Loads the subpaths in the path represented by object.
 */
void FilesystemPath::loadSubpaths() const
{
	_subpaths.clear();

	std::vector<std::string> subpaths;
	if (!_impl->subpathsInDirectory(subpaths))
		return;

	std::transform(subpaths.begin(), subpaths.end(), std::back_inserter(_subpaths),
			[](const auto& subpath) {
				return std::make_unique<FilesystemPath>(subpath);
			});

	_subpathsLoaded = true;
}

} // namespace utils
} // namespace retdec
