/**
 * @file src/unpackertool/plugin_mgr.h
 * @brief PluginMgr declaration which is singleton manager for plugin loading.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef UNPACKERTOOL_PLUGIN_MGR_H
#define UNPACKERTOOL_PLUGIN_MGR_H

#include <cctype>
#include <map>
#include <string>
#include <vector>

#include "tl-cpputils/os.h"
#include "singleton.h"

namespace unpackertool {

#ifdef OS_WINDOWS
#define PLUGIN_SUFFIX           "dll"
#define PLUGIN_SUFFIX_LEN       3
#else
#define PLUGIN_SUFFIX           "so"
#define PLUGIN_SUFFIX_LEN       2
#endif

#define WILDCARD_ALL_VERSIONS   ""

class Plugin;

/**
 * @brief Case-insensitive string comparison.
 *
 * The structure for case-insensitive string comparison.
 */
struct IcaseStringCompare
{
	/**
	 * Functor used as compare function.
	 *
	 * @param lhs Left-hand side of compare.
	 * @param rhs Right-hand side of compare.
	 *
	 * @return True if the strings are case-insensitivelly equal, otherwise false.
	 */
	bool operator ()(const std::string& lhs, const std::string& rhs) const
	{
		if (lhs.length() < rhs.length())
			return true;
		else if (lhs.length() > rhs.length())
			return false;
		else
		{
			for (size_t i = 0; i < lhs.length(); ++i)
			{
				// Cast to unsigned char required because of MSVC assert
				const unsigned char lc = lhs[i];
				const unsigned char rc = rhs[i];
				if (std::tolower(lc) != std::tolower(rc))
					return std::tolower(lc) < std::tolower(rc);
			}
		}

		return false;
	}
};

using PluginList = std::vector<Plugin*>; ///< Type for list of plugins.
using PluginTable = std::map<std::string, PluginList, IcaseStringCompare>; ///< Mapping of case-insensitive packer name to list of plugins.
using CreatePluginFunc = Plugin* (*)(); ///< Type for plugin registration function.

/**
 * @brief The manager of unpacking plugins.
 *
 * PluginMgr is singleton representing the plugin manager.
 * It loads and register the plugin. It can also find the
 * matching plugins for the specified plugin packer and version.
 * Plugins are stored in the table where packer name is
 * case-insensitively mapped to the list of plugins that is
 * capable of unpacking this packer. Every plugin contains the
 * regular expression matching the version of packers it is
 * able to unpack.
 */
class PluginMgr
{
	IS_SINGLETON(PluginMgr)
public:
	~PluginMgr();

	bool loadPlugin(const std::string& path);
	void loadPlugins(const std::string& dirPath);

	const PluginTable& plugins() const;
	PluginList matchingPlugins(const std::string& packerName, const std::string& packerVersion) const;

private:
	PluginMgr();
	PluginMgr(const PluginMgr&);
	PluginMgr& operator =(const PluginMgr&);

	PluginTable _plugins; ///< Table of registered plugins.
};
#define sPluginMgr      Singleton<PluginMgr>::instance()

} // namespace unpackertool

#endif
