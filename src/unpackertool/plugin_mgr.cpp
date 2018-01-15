/**
 * @file src/unpackertool/plugin_mgr.cpp
 * @brief PluginMgr implementation which is singleton manager for plugin loading.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>
#include <regex>

#include "retdec/utils/string.h"
#include "retdec/unpacker/plugin.h"
#include "plugin_mgr.h"

#include "plugins/mpress/mpress.h"
#include "plugins/upx/upx.h"

using namespace retdec::utils;

namespace retdec {
namespace unpackertool {

const std::vector<Plugin*> PluginMgr::plugins =
{
	mpress_plugin,
	upx_plugin
};

/**
 * Find the matching plugins in the registered plugins table.
 *
 * @param packerName The packer name for which the plugins are found.
 * @param packerVersion The packer version for which the plugins are found.
 *
 * @return The list of matched plugins.
 */
PluginList PluginMgr::matchingPlugins(const std::string& packerName, const std::string& packerVersion)
{
	// Iterate over all plugins for this packer name and match it against the used packer version
	PluginList matchedPlugins;
	for (const auto& plugin : plugins)
	{
		if (!utils::areEqualCaseInsensitive(plugin->getInfo()->name, packerName))
			continue;

		matchedPlugins.push_back(plugin);
	}

	// For wildcard just return the all versions of this packers
	if (packerVersion == WILDCARD_ALL_VERSIONS)
		return matchedPlugins;

	PluginList result;
	for (const auto& plugin : matchedPlugins)
	{
		// Non case-sensitive regular expressions to match against packerVersion
		std::regex versionRegex(plugin->getInfo()->packerVersion, std::regex::icase);
		if (std::regex_search(packerVersion, versionRegex))
			result.push_back(plugin);
	}

	return result;
}

} // namepsace unpackertool
} // namepsace retdec
