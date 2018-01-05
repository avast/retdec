/**
 * @file src/unpackertool/plugin_mgr.cpp
 * @brief PluginMgr implementation which is singleton manager for plugin loading.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>
#include <regex>

#include "tl-cpputils/filesystem_path.h"
#include "tl-cpputils/string.h"
#include "unpacker/lib_loader.h"
#include "unpacker/plugin.h"
#include "plugin_mgr.h"

using namespace tl_cpputils;

namespace unpackertool {

/**
 * Constructor.
 */
PluginMgr::PluginMgr() : _plugins()
{
}

/**
 * Destructor.
 */
PluginMgr::~PluginMgr()
{
	for (auto& pluginPair : _plugins)
	{
		for (auto& plugin : pluginPair.second)
		{
			// We need to unload the library after the plugin is destroyed
			// This cannot be done in Plugin destructor as we are destructing the heap
			// of the plugin, which resides in the library address space
			LibHandle handle = plugin->getHandle();
			delete plugin;
			LibLoader::unloadLibrary(handle);
		}
	}
}

/**
 * Loads the plugin with the specified name.
 *
 * @param name The name of the plugin.
 *
 * @return True if the load was successful, otherwise false.
 */
bool PluginMgr::loadPlugin(const std::string& name)
{
	// Load the library representing the plugin
	LibHandle lib = LibLoader::loadLibrary(name);
	if (!lib)
	{
		std::cerr << "Failed to load plugin '" << name << "'. Reason: " << LibLoader::getLastError() << std::endl;
		return false;
	}

	// Find the registration function
	CreatePluginFunc createPlugin;
	if ((createPlugin = LibLoader::loadFunction<CreatePluginFunc>(lib, REGISTER_PLUGIN_FUNCTION_NAME)) == nullptr)
	{
		LibLoader::unloadLibrary(lib);
		return false;
	}

	// Register the plugin
	Plugin* plugin = createPlugin();
	if (plugin == nullptr)
	{
		LibLoader::unloadLibrary(lib);
		return false;
	}

	// Initialize
	plugin->init();

	// Check whether initialization set Plugin::Info structure
	const Plugin::Info* pluginInfo = plugin->getInfo();
	if (pluginInfo->isUninitialized())
	{
		LibLoader::unloadLibrary(lib);
		return false;
	}

	// Set the handle to the library so we can properly free it
	plugin->setHandle(lib);

	// Put it into table
	_plugins[pluginInfo->name].push_back(plugin);
	return true;
}

/**
 * Load all plugins recursively in the specified path.
 *
 * @param dirPath Path to traverse recursively.
 */
void PluginMgr::loadPlugins(const std::string& dirPath)
{
	FilesystemPath path(dirPath);
	for (const auto& subpath : path)
	{
		// In case of directory, recursively call loadPlugins
		if (subpath->isDirectory())
		{
			loadPlugins(subpath->getPath());
		}
		else
		{
			// if PLUGIN_SUFFIX is at the end of the name of the file
			if (tl_cpputils::endsWith(subpath->getPath(), PLUGIN_SUFFIX))
				loadPlugin(subpath->getPath());
		}
	}
}

/**
 * Returns the table of registered plugins.
 *
 * @return The table of plugins.
 */
const PluginTable& PluginMgr::plugins() const
{
	return _plugins;
}

/**
 * Find the matching plugins in the registered plugins table.
 *
 * @param packerName The packer name for which the plugins are found.
 * @param packerVersion The packer version for which the plugins are found.
 *
 * @return The list of matched plugins.
 */
PluginList PluginMgr::matchingPlugins(const std::string& packerName, const std::string& packerVersion) const
{
	// Find the packer name in plugin table to extract list of plugins for this packer
	PluginTable::const_iterator itr = _plugins.find(packerName);
	if (itr == _plugins.end())
		return PluginList();

	// Iterate over all plugins for this packer name and match it against the used packer version
	PluginList matchedPlugins;
	const PluginList& pluginList = itr->second;

	// For wildcard just return the all versions of this packers
	if (packerVersion == WILDCARD_ALL_VERSIONS)
		return pluginList;

	for (const auto& plugin : pluginList)
	{
		// Non case-sensitive regular expressions to match against packerVersion
		std::regex versionRegex(plugin->getInfo()->packerVersion, std::regex::icase);
		if (std::regex_search(packerVersion, versionRegex))
			matchedPlugins.push_back(plugin);
	}

	return matchedPlugins;
}

} // namepsace unpackertool
