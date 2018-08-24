/**
 * @file src/stacofin/stacofin.cpp
 * @brief Static code finder library.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>
#include <sstream>
#include <string>

#include "retdec/stacofin/stacofin.h"
#include "yaracpp/yara_detector/yara_detector.h"
#include "retdec/loader/loader/image.h"
#include "retdec/utils/string.h"

/**
 * Set \c debug_enabled to \c true to enable this LOG macro.
 */
#define LOG \
	if (!debug_enabled) {} \
	else std::cout << std::showbase
static bool debug_enabled = false;

using namespace retdec::utils;
using namespace yaracpp;
using namespace retdec::loader;

namespace retdec {
namespace stacofin {

//
//==============================================================================
// Anonymous namespace.
//==============================================================================
//

namespace {

using namespace retdec;

void selectSignaturesWithName(
		const std::set<std::string>& src,
		std::set<std::string>& dst,
		const std::string& partOfName)
{
	for (const auto& sig : src)
	{
		if (sig.find(partOfName) != std::string::npos)
		{
			dst.insert(sig);
		}
	}
}

void selectSignaturesWithNames(
		const std::set<std::string>& src,
		std::set<std::string>& dst,
		const std::set<std::string>& partOfName,
		const std::set<std::string>& notPartOfName)
{
	for (const auto& sig : src)
	{
		bool allOk = true;

		for (auto& p : partOfName)
		{
			if (sig.find(p) == std::string::npos)
			{
				allOk = false;
				break;
			}
		}

		for (auto& p : notPartOfName)
		{
			if (sig.find(p) != std::string::npos)
			{
				allOk = false;
				break;
			}
		}

		if (allOk)
		{
			dst.insert(sig);
		}
	}
}

std::set<std::string> selectSignaturePaths(
		const retdec::loader::Image& image,
		const retdec::config::Config& c)
{
	std::set<std::string> sigs;

	// Add all statically linked signatures specified by user.
	//
	sigs = c.parameters.userStaticSignaturePaths;

	// Select only specific signatures from retdec's database.
	//
	auto& allSigs = c.parameters.staticSignaturePaths;

	std::set<std::string> vsSigsAll;
	std::set<std::string> vsSigsSpecific;
	if (c.tools.isMsvc())
	{
		selectSignaturesWithName(allSigs, sigs, "ucrt");

		std::string arch;
		if (c.architecture.isX86())
		{
			arch = "x86";
		}
		else if (c.architecture.isArmOrThumb())
		{
			arch = "arm";
		}

		std::size_t major = 0;
		std::size_t minor = 0;
		if (auto* pe = dynamic_cast<const retdec::fileformat::PeFormat*>(
				image.getFileFormat()))
		{
			major = pe->getMajorLinkerVersion();
			minor = pe->getMinorLinkerVersion();

			if (major == 7 && minor == 1)
			{
				selectSignaturesWithName(allSigs, vsSigsSpecific, "-vs-2003");
			}
			else if (major == 8 && minor == 0)
			{
				selectSignaturesWithName(allSigs, vsSigsSpecific, "-vs-2005");
			}
			else if (major == 9 && minor == 0)
			{
				selectSignaturesWithName(allSigs, vsSigsSpecific, "-vs-2008");
			}
			else if (major == 10 && minor == 0)
			{
				selectSignaturesWithName(allSigs, vsSigsSpecific, "-vs-2010");
			}
			else if (major == 11 && minor == 0)
			{
				selectSignaturesWithName(allSigs, vsSigsSpecific, "-vs-2012");
			}
			else if (major == 12 && minor == 0)
			{
				selectSignaturesWithName(allSigs, vsSigsSpecific, "-vs-2013");
			}
			else if (major == 14 && minor == 0)
			{
				selectSignaturesWithName(allSigs, vsSigsSpecific, "-vs-2015");
			}
			else if ((major == 15 && minor == 0)
					|| (major == 14 && minor == 10))
			{
				selectSignaturesWithName(allSigs, vsSigsSpecific, "-vs-2017");
			}
		}

		for (auto& vs : c.tools)
		{
			bool all = false;
			std::string pattern = arch;

			if (vs.isMsvc("debug"))
			{
				pattern += "debug-vs-";
			}
			else
			{
				pattern += "-vs-";
			}

			if (vs.isMsvc("7.1"))
			{
				pattern += "2003";
			}
			else if (vs.isMsvc("8.0"))
			{
				pattern += "2005";
			}
			else if (vs.isMsvc("9.0"))
			{
				pattern += "2008";
			}
			else if (vs.isMsvc("10.0"))
			{
				pattern += "2010";
			}
			else if (vs.isMsvc("11.0"))
			{
				pattern += "2012";
			}
			else if (vs.isMsvc("12.0"))
			{
				pattern += "2013";
			}
			else if (vs.isMsvc("14.0"))
			{
				pattern += "2015";
			}
			else if (vs.isMsvc("15.0"))
			{
				pattern += "2017";
			}
			else
			{
				all = true;
			}

			if (all)
			{
				selectSignaturesWithName(allSigs, vsSigsAll, pattern);
			}
			else
			{
				selectSignaturesWithName(allSigs, vsSigsSpecific, pattern);
			}
		}
	}
	if (!vsSigsSpecific.empty())
	{
		sigs.insert(vsSigsSpecific.begin(), vsSigsSpecific.end());
	}
	else
	{
		sigs.insert(vsSigsAll.begin(), vsSigsAll.end());
	}

	if (c.tools.isMingw())
	{
		if (c.tools.isTool("4.7.3"))
		{
			selectSignaturesWithName(allSigs, sigs, "mingw-4.7.3");
		}
		else if (c.tools.isTool("4.4.0"))
		{
			selectSignaturesWithName(allSigs, sigs, "mingw-4.4.0");
		}
	}
	else if (c.tools.isGcc() || c.tools.isLlvm())
	{
		if (c.tools.isPspGcc()
				&& c.tools.isTool("4.3.5"))
		{
			selectSignaturesWithNames(
					allSigs,
					sigs,
					{"psp-gcc-4.3.5"},
					{"pic32", "uClibc"});
		}
		else if (c.tools.isPic32()
				&& c.tools.isTool("4.5.2"))
		{
			selectSignaturesWithNames(
					allSigs,
					sigs,
					{"pic32-gcc-4.5.2"},
					{"psp", "uClibc"});
		}
		else if (c.fileFormat.isPe())
		{
			if (c.tools.isTool("4.7.3"))
			{
				selectSignaturesWithName(allSigs, sigs, "mingw-4.7.3");
			}
			else if (c.tools.isTool("4.4.0"))
			{
				selectSignaturesWithName(allSigs, sigs, "mingw-4.4.0");
			}
		}
		else // if (c.tools.isGcc())
		{
			if (c.tools.isTool("4.8.3"))
			{
				selectSignaturesWithNames(
						allSigs,
						sigs,
						{"gcc-4.8.3"},
						{"psp", "pic32", "uClibc"});
			}
			else if (c.tools.isTool("4.7.2"))
			{
				selectSignaturesWithNames(
						allSigs,
						sigs,
						{"gcc-4.7.2"},
						{"psp", "pic32", "uClibc"});
			}
			else if (c.tools.isTool("4.4.1"))
			{
				selectSignaturesWithNames(
						allSigs,
						sigs,
						{"gcc-4.4.1"},
						{"psp", "pic32", "uClibc"});
			}
			else if (c.tools.isTool("4.5.2"))
			{
				selectSignaturesWithNames(
						allSigs,
						sigs,
						{"gcc-4.5.2"},
						{"psp", "pic32", "uClibc"});
			}
		}
	}

	if (c.fileFormat.isIntelHex() || c.fileFormat.isRaw())
	{
		if (c.architecture.isMips())
		{
			selectSignaturesWithNames(allSigs, sigs, {"psp-gcc"}, {"uClibc"});
		}
		if (c.architecture.isPic32())
		{
			selectSignaturesWithNames(allSigs, sigs, {"pic32-gcc"}, {"uClibc"});
		}
	}

	if (c.tools.isDelphi())
	{
		selectSignaturesWithName(allSigs, sigs, "kb7");
	}

	return sigs;
}

} // namespace anonymous

//
//==============================================================================
// Reference.
//==============================================================================
//

Reference::Reference(
		std::size_t o,
		const std::string& n,
		utils::Address a,
		utils::Address t,
		DetectedFunction* tf,
		bool k)
		:
		offset(o),
		name(n),
		address(a),
		target(t),
		targetFnc(tf),
		ok(k)
{

}

//
//==============================================================================
// DetectedFunction.
//==============================================================================
//

bool DetectedFunction::operator<(const DetectedFunction& o) const
{
	if (address == o.address)
	{
		if (names.empty())
		{
			return true;
		}
		else if (o.names.empty())
		{
			return false;
		}
		else
		{
			return getName() < o.getName();
		}
	}
	else
	{
		return address < o.address;
	}
}

bool DetectedFunction::allRefsOk() const
{
	for (auto& ref : references)
	{
		if (!ref.ok)
		{
			return false;
		}
	}

	return true;
}

std::size_t DetectedFunction::countRefsOk() const
{
	std::size_t ret = 0;

	for (auto& ref : references)
	{
		ret += ref.ok;
	}

	return ret;
}

float DetectedFunction::refsOkShare() const
{
	return references.empty()
			? 1.0
			: float(countRefsOk()) / float(references.size());
}

std::string DetectedFunction::getName() const
{
	return names.empty() ? "" : names.front();
}

bool DetectedFunction::isTerminating() const
{
	// TODO: couple names with source signaturePath to make sure we do not
	// hit wrong functions?
	//
	static std::set<std::string> termNames = {
			"exit",
			"_exit",
	};

	for (auto& n : names)
	{
		if (termNames.count(n))
		{
			return true;
		}
	}

	return false;
}

bool DetectedFunction::isThumb() const
{
	return utils::containsCaseInsensitive(signaturePath, "thumb");
}

/**
 * Parse string with references from meta attribute.
 *
 * @param refsString references string
 */
void DetectedFunction::setReferences(const std::string &refsString)
{
	std::string name;
	std::size_t offset;
	std::stringstream refsStream(refsString);

	for (;;) {
		refsStream >> std::hex >> offset;
		refsStream >> name;
		if (!refsStream) {
			break;
		}

		references.push_back({offset, name});
	}
}

/**
 * Setting an address will also fix addresses of all the function's references.
 */
void DetectedFunction::setAddress(retdec::utils::Address a)
{
	address = a;
	for (auto& r : references)
	{
		r.address = r.offset + a;
	}
}

retdec::utils::Address DetectedFunction::getAddress() const
{
	return address;
}

//
//==============================================================================
// Finder.
//==============================================================================
//

/**
 * Default constructor.
 */
Finder::Finder()
{
}

/**
 * Default destructor.
 */
Finder::~Finder()
{
}

/**
 * Clear all previous results.
 */
void Finder::clear()
{
	coveredCode.clear();
	detectedFunctions.clear();
}

/**
 * Search for static code in input file.
 *
 * @param image input file image
 * @param yaraFile static code signatures
 */
void Finder::search(
	const Image& image,
	const std::string& yaraFile)
{
	// Get FileFormat instance.
	const auto* fileFormat = image.getFileFormat();
	if (!fileFormat) {
		return;
	}

	// Start Yara detector.
	YaraDetector detector;
	detector.addRuleFile(yaraFile);
	auto inputBytes = fileFormat->getLoadedBytes();
	detector.analyze(inputBytes);
	if (!detector.isInValidState()) {
		return;
	}

	// Iterate over detected rules.
	isSorted = false;
	for (const YaraRule &detectedRule : detector.getDetectedRules()) {
		DetectedFunction detectedFunction;
		detectedFunction.signaturePath = yaraFile;

		for (const YaraMeta &ruleMeta : detectedRule.getMetas()) {
			if (ruleMeta.getId() == "name") {
				detectedFunction.names.push_back(ruleMeta.getStringValue());
			}
			if (ruleMeta.getId() == "size") {
				detectedFunction.size = ruleMeta.getIntValue();
			}
			if (ruleMeta.getId() == "refs") {
				const auto &refs = ruleMeta.getStringValue();
				detectedFunction.setReferences(refs);
			}
			if (ruleMeta.getId() == "altNames") {
				std::string name;
				const auto &altNames = ruleMeta.getStringValue();
				std::istringstream ss(altNames, std::istringstream::in);
				while(ss >> name) {
					detectedFunction.names.push_back(name);
				}
			}
		}

		// Iterate over all matches.
		for (const YaraMatch &ruleMatch : detectedRule.getMatches()) {
			// This is different for every match.
			detectedFunction.offset = ruleMatch.getOffset();
			unsigned long long address = 0;
			if (!fileFormat->getAddressFromOffset(
						address, detectedFunction.offset)) {
				// Cannot get address. Maybe report error?
				continue;
			}

			// Store data.
			detectedFunction.setAddress(address);
			coveredCode.insert(AddressRange(
					address,
					address + detectedFunction.size));
			detectedFunctions.push_back(detectedFunction);
		}
	}
}

void Finder::search(
	const retdec::loader::Image& image,
	const std::set<std::string>& yaraFiles)
{
	for (const auto& f : yaraFiles)
	{
		search(image, f);
	}
}

void Finder::search(
	const retdec::loader::Image& image,
	const retdec::config::Config& config)
{
	auto sigPaths = selectSignaturePaths(image, config);
	search(image, sigPaths);
}

/**
 * Return detected code coverage.
 *
 * @return covered code
 */
CoveredCode Finder::getCoveredCode()
{
	return coveredCode;
}

/**
 * Return detected functions sorted by their address.
 *
 * @return sorted detected functions
 */
const std::vector<DetectedFunction>& Finder::getDectedFunctions()
{
	sort();
	return detectedFunctions;
}

/**
 * Sort detected functions.
 *
 * Functions are sorted by their address, if detection address is same bigger
 * detection is frist.
 */
void Finder::sort()
{
	if (!isSorted)
	{
		std::sort(detectedFunctions.begin(), detectedFunctions.end(),
			[](DetectedFunction i, DetectedFunction j)
			{
				if (i.getAddress() == j.getAddress())
				{
					return i.size > j.size;
				}
				return i.getAddress() < j.getAddress();
			});
		isSorted = true;
	}
}

} // namespace stacofin
} // namespace retdec
