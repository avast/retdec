/**
 * @file src/tl-cpputils/filesystem_path.cpp
 * @brief FilesystemPath class implementation for unified work with filepaths.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <string>

#include "tl-cpputils/filesystem_path.h"
#include "tl-cpputils/os.h"
#include "tl-cpputils/string.h"
#include "tl-cpputils/value.h"

#ifdef OS_WINDOWS
	#include <windows.h>
	#include <shlwapi.h>
#else
	#include <sys/types.h>
	#include <dirent.h>
	#include <sys/stat.h>
	#include <libgen.h>
#endif

namespace tl_cpputils {

class FilesystemPathImpl
{
public:
	FilesystemPathImpl(const std::string& path)
		: _path(), _parentPath(), _subpaths(), _exists(), _isFile(), _isDirectory(), _isAbsolute()
	{
		changePath(path);
	}

	FilesystemPathImpl(const FilesystemPathImpl& rhs)
		: _path(rhs._path), _parentPath(rhs._parentPath), _subpaths(rhs._subpaths), _exists(rhs._exists),
		_isFile(rhs._isFile), _isDirectory(rhs._isDirectory), _isAbsolute(rhs._isAbsolute) {}
	virtual ~FilesystemPathImpl() = default;

	void reset()
	{
		_parentPath = {};
		_subpaths = {};
		_exists = {};
		_isFile = {};
		_isDirectory = {};
		_isAbsolute = {};
	}

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
		reset();
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
	Maybe<std::string> _absolutePath, _parentPath;
	Maybe<std::vector<std::string>> _subpaths;
	Maybe<bool> _exists, _isFile, _isDirectory, _isAbsolute;
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
		if (_absolutePath.isDefined())
			return _absolutePath;

		char absolutePath[MAX_PATH] = { '\0' };
		if (GetFullPathName(_path.c_str(), MAX_PATH, absolutePath, nullptr) == 0)
			return {};

		_absolutePath = std::string(absolutePath);
		return _absolutePath;
	}

	virtual std::string getParentPath() override
	{
		if (_parentPath.isDefined())
			return _parentPath;

		// PathRemoveFileSpec() supports only MAX_PATH long paths and modify its parameter
		char parentPathStr[MAX_PATH] = { '\0' };
		strncpy(parentPathStr, _path.c_str(), MAX_PATH - 1);

		PathRemoveFileSpec(parentPathStr);

		_parentPath = std::string(parentPathStr);
		return _parentPath;
	}

	virtual bool subpathsInDirectory(std::vector<std::string>& subpaths) override
	{
		using namespace std::string_literals;

		if (_subpaths.isDefined())
		{
			subpaths = _subpaths.getValue();
			return true;
		}

		WIN32_FIND_DATA ffd;

		// We need to add wildcard to examine the content of the directory
		std::string examineDir = _path;
		examineDir.append(pathSeparator + "*"s);

		subpaths.clear();
		HANDLE hFnd = FindFirstFile(examineDir.c_str(), &ffd);
		if (hFnd == reinterpret_cast<HANDLE>(-1))
		{
			_subpaths = std::vector<std::string>{};
			return false;
		}

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

		_subpaths = subpaths;
		return true;
	}

	virtual bool exists() override
	{
		if (_exists.isDefined())
			return _exists;

		_exists = PathFileExists(_path.c_str());
		return _exists;
	}

	virtual bool isFile() override
	{
		if (_isFile.isDefined())
			return _isFile;

		isDirectory();
		return _isFile;
	}

	virtual bool isDirectory() override
	{
		if (_isDirectory.isDefined())
			return _isDirectory;

		WIN32_FIND_DATA ffd;
		if (FindFirstFile(_path.c_str(), &ffd) == reinterpret_cast<HANDLE>(-1))
		{
			_exists = false;
			_isDirectory = false;
			_isFile = false;
			return false;
		}

		_exists = true;
		_isDirectory = ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY;
		_isFile = !_isDirectory;
		return _isDirectory;
	}

	virtual bool isAbsolute() override
	{
		if (_isAbsolute.isDefined())
			return _isAbsolute;

		_isAbsolute = !PathIsRelative(_path.c_str());
		return _isAbsolute;
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
		if (_absolutePath.isDefined())
			return _absolutePath;

		char absolutePath[PATH_MAX] = { '\0' };
		if (realpath(_path.c_str(), absolutePath) == nullptr)
			return {};

		_absolutePath = std::string(absolutePath);
		return _absolutePath;
	}

	virtual std::string getParentPath() override
	{
		if (_parentPath.isDefined())
			return _parentPath;

		// dirname() can modify the path provided in parameter, so we need to make copy
		char* copyPathStr = new char[_path.length() + 1];
		strcpy(copyPathStr, _path.c_str());

		// get the parent directory by calling dirname()
		char* parentPathStr = dirname(copyPathStr);

		// copy the parent path into the string, so we can free the memory
		_parentPath = std::string(parentPathStr);
		delete[] copyPathStr;
		return _parentPath;
	}

	virtual bool subpathsInDirectory(std::vector<std::string>& subpaths) override
	{
		if (_subpaths.isDefined())
		{
			subpaths = _subpaths.getValue();
			return true;
		}

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

		_subpaths = subpaths;
		return true;
	}

	virtual bool exists() override
	{
		if (_exists.isDefined())
			return _exists;

		isDirectory();
		return _exists;
	}

	virtual bool isFile() override
	{
		if (_isFile.isDefined())
			return _isFile;

		isDirectory();
		return _isFile;
	}

	virtual bool isDirectory() override
	{
		if (_isDirectory.isDefined())
			return _isDirectory;

		struct stat st;
		if (stat(_path.c_str(), &st) != 0)
		{
			_exists = false;
			_isDirectory = false;
			_isFile = false;
			return false;
		}

		_exists = true;
		_isDirectory = S_ISDIR(st.st_mode);
		_isFile = S_ISREG(st.st_mode);
		return _isDirectory;
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

	for (const auto& subpath : subpaths)
	{
		auto fsSubpath = std::make_unique<FilesystemPath>(subpath);
		_subpaths.push_back(std::move(fsSubpath));
	}

	_subpathsLoaded = true;
}

} // namespace tl_cpputils
