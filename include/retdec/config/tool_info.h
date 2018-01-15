/**
 * @file include/retdec/config/tool_info.h
 * @brief Decompilation configuration manipulation: tool info.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_CONFIG_TOOL_INFO_H
#define RETDEC_CONFIG_TOOL_INFO_H

#include <string>

#include "retdec/config/base.h"

namespace retdec {
namespace config {

/**
 * Represents tools used to create/manipulate input binary (i.e compiler, packer).
 */
class ToolInfo
{
	public:
		static ToolInfo fromJsonValue(const Json::Value& val);
		Json::Value getJsonValue() const;

		/// @name Tool query methods.
		/// @{
		bool isUnknown() const;
		bool isKnown() const;
		bool isBorland() const;
		bool isGcc() const;
		bool isIntel() const;
		bool isOpenWatcom() const;
		bool isMsvc(const std::string& version = "") const;
		bool isTool(const std::string& n) const;
		bool isToolVersion(const std::string& v) const;
		bool isCompiler() const;
		bool isLinker() const;
		bool isInstaller() const;
		bool isPacker() const;
		bool isUnknownType() const;
		bool isKnownType() const;
		/// @}

		/// @name Tool set methods.
		/// @{
		void setType(const std::string& t);
		void setName(const std::string& n);
		void setVersion(const std::string& n);
		void setMajorVersion(unsigned int v);
		void setMinorVersion(unsigned int v);
		void setPatchVersion(unsigned int v);
		void setAdditionalInfo(const std::string& i);
		void setPercentage(double p);
		void setIdenticalSignificantNibbles(unsigned i);
		void setTotalSignificantNibbles(unsigned i);
		void setIsFromHeuristics(bool h);

		void setIsUnknown();
		void setIsBorland();
		void setIsGcc();
		void setIsIntel();
		void setIsOpenWatcom();
		void setIsVisualStudio();
		/// @}

		/// @name Tool get methods.
		/// @{
		std::string getType() const;
		std::string getName() const;
		std::string getVersion() const;
		std::string getAdditionalInfo() const;
		unsigned int getMajorVersion() const;
		unsigned int getMinorVersion() const;
		unsigned int getPatchVersion() const;
		double getPercentage() const;
		unsigned getIdenticalSignificantNibbles() const;
		unsigned getTotalSignificantNibbles() const;
		bool isFromHeuristics() const;
		/// @}

		bool operator==(const ToolInfo& val) const;

	private:
		std::string _type;
		std::string _name;
		std::string _additionalInfo;

		/// Entire tool version string. If it has an expected format it may
		/// be parsed into its components @c majorVersion @c minorVersion
		/// and @c patchVersion.
		std::string _version;
		unsigned int _majorVersion = 0;
		unsigned int _minorVersion = 0;
		unsigned int _patchVersion = 0;

		/// Probability that the tool was actually used. This does not have
		/// to be set. It is significant only if the value is not 0.0.
		double _percentage = 0.0;

		/// Total number of significant nibbles in signature recognizing
		/// this tool.
		unsigned _totalSignificantNibbles = 0;
		/// Number of significant nibbles that were actually found.
		unsigned _identicalSignificantNibbles = 0;

		/// Were heuristics used to detect usage of this tool?
		bool _heuristics = false;
};

/**
 * Sequential container of tool informations.
 * The order of tools in this container is important. The first one is the most,
 * and the last one the least, significant.
 */
class ToolInfoContainer : public BaseSequentialContainer<ToolInfo>
{
	public:
		const ToolInfo* getToolByName(const std::string& name);
		const ToolInfo* getToolWithMaxPercentage();
		const ToolInfo* getToolMostSignificant();

		bool isTool(const std::string& name) const;

		/// @name Tool container query methods.
		/// Methods find out it the container contains specific tool
		/// using the @c isTool() method.
		/// Because there might be several tools in the container,
		/// several of these methods may return true at the same time.
		/// @{
		bool isGcc() const;
		bool isFasm() const;
		bool isLlvm() const;
		bool isPic32() const;
		bool isMingw() const;
		bool isDelphi() const;
		bool isWatcom() const;
		bool isIntel() const;
		bool isPspGcc() const;
		bool isBorland() const;
		bool isMsvc(const std::string& version = "") const;
		bool isThumbCompiler() const;
		/// @}
};

} // namespace config
} // namespace retdec

#endif
