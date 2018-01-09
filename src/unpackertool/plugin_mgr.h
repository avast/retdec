/**
 * @file src/unpackertool/plugin_mgr.h
 * @brief PluginMgr declaration which is singleton manager for plugin loading.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef UNPACKERTOOL_PLUGIN_MGR_H
#define UNPACKERTOOL_PLUGIN_MGR_H

#include <cctype>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace retdec {
namespace unpackertool {

#define WILDCARD_ALL_VERSIONS   ""

class Plugin;

using PluginList = std::vector<Plugin*>; ///< Type for list of plugins.

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
public:
	PluginMgr(const PluginMgr&) = delete;

	static const PluginList plugins;

	static PluginList matchingPlugins(const std::string& packerName, const std::string& packerVersion);

private:
	PluginMgr() = default;
};

} // namespace unpackertool
} // namespace retdec

#endif
