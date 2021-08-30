/**
 * @file src/stacofin/stacofin.cpp
 * @brief Static code finder library.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <sstream>
#include <string>

#include "retdec/fileformat/fileformat.h"
#include "retdec/loader/loader/image.h"
#include "retdec/stacofin/stacofin.h"
#include "retdec/utils/string.h"
#include "retdec/utils/filesystem.h"
#include "retdec/yaracpp/yara_detector.h"

/**
 * Set \c debug_enabled to \c true to enable this LOG macro.
 */
#define LOG \
	if (!debug_enabled) {} \
	else std::cout << std::showbase
static bool debug_enabled = false;

using namespace retdec::common;
using namespace retdec::loader;
using namespace retdec::utils;
using namespace retdec::yaracpp;

namespace retdec {
namespace stacofin {

//
//==============================================================================
// Anonymous namespace.
//==============================================================================
//

namespace {

using namespace retdec;

void selectSignaturesWithNames(
		const std::set<std::string>& src,
		std::set<std::string>& dst,
		const std::set<std::string>& partOfName,
		const std::set<std::string>& notPartOfName = std::set<std::string>())
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

void getAllSignatureFiles(
		const fs::path& fp,
		std::set<std::string>& signFiles,
		const std::set<std::string>& suffixes = {".yar", ".yara", ".yarac"})
{
	if (fs::is_regular_file(fp)
			&& std::any_of(suffixes.begin(), suffixes.end(),
			[&] (const auto &suffix)
			{
				return endsWith(fp.string(), suffix);
			}
		))
	{
		signFiles.insert(fs::absolute(fp).string());
	}
	else if (fs::is_directory(fp))
	{
		for (auto& s : fs::directory_iterator(fp))
		{
			getAllSignatureFiles(s, signFiles);
		}
	}
}

std::set<std::string> selectSignaturePaths(
		const retdec::loader::Image& image,
		const retdec::config::Config& c)
{
	// Add all statically linked signatures specified by user.
	//
	std::set<std::string> sigs;
	for (auto& p : c.parameters.userStaticSignaturePaths)
	{
		getAllSignatureFiles(fs::path(p), sigs);
	}

	// Select only specific signatures from retdec's database.
	//
	std::set<std::string> allSigs;
	for (auto& p : c.parameters.staticSignaturePaths)
	{
		getAllSignatureFiles(fs::path(p), allSigs);
	}

	std::string archSize = std::to_string(image.getWordLength());
	std::string format;
	if (dynamic_cast<const fileformat::ElfFormat*>(image.getFileFormat()))
	{
		format = "elf";
	}
	else if (dynamic_cast<const fileformat::PeFormat*>(image.getFileFormat()))
	{
		format = "pe";
	}
	std::string arch;
	if (c.architecture.isX86_32())
	{
		arch = "x86";
	}
	else if (c.architecture.isX86_64())
	{
		arch = "x64";
	}
	else if (c.architecture.isArm32OrThumb())
	{
		arch = "arm";
	}

	std::set<std::string> vsSigsAll;
	std::set<std::string> vsSigsSpecific;
	if (c.tools.isMsvc())
	{
		selectSignaturesWithNames(
				allSigs,
				sigs,
				{arch, archSize, format, "ucrt"}
		);

		std::size_t major = 0;
		std::size_t minor = 0;
		if (auto* pe = dynamic_cast<const retdec::fileformat::PeFormat*>(
				image.getFileFormat()))
		{
			major = pe->getMajorLinkerVersion();
			minor = pe->getMinorLinkerVersion();

			if (major == 7 && minor == 1)
			{
				selectSignaturesWithNames(
						allSigs,
						vsSigsSpecific,
						{arch, archSize, format, "-vs-2003"}
				);
			}
			else if (major == 8 && minor == 0)
			{
				selectSignaturesWithNames(
						allSigs,
						vsSigsSpecific,
						{arch, archSize, format, "-vs-2005"}
				);
			}
			else if (major == 9 && minor == 0)
			{
				selectSignaturesWithNames(
						allSigs,
						vsSigsSpecific,
						{arch, archSize, format, "-vs-2008"}
				);
			}
			else if (major == 10 && minor == 0)
			{
				selectSignaturesWithNames(
						allSigs,
						vsSigsSpecific,
						{arch, archSize, format, "-vs-2010"}
				);
			}
			else if (major == 11 && minor == 0)
			{
				selectSignaturesWithNames(
						allSigs,
						vsSigsSpecific,
						{arch, archSize, format, "-vs-2012"}
				);
			}
			else if (major == 12 && minor == 0)
			{
				selectSignaturesWithNames(
						allSigs,
						vsSigsSpecific,
						{arch, archSize, format, "-vs-2013"}
				);
			}
			else if (major == 14 && minor == 0)
			{
				selectSignaturesWithNames(
						allSigs,
						vsSigsSpecific,
						{arch, archSize, format, "-vs-2015"}
				);
			}
			else if ((major == 15 && minor == 0)
					|| (major == 14 && minor == 10))
			{
				selectSignaturesWithNames(
						allSigs,
						vsSigsSpecific,
						{arch, archSize, format, "-vs-2017"}
				);
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
				selectSignaturesWithNames(
						allSigs,
						vsSigsAll,
						{arch, archSize, format, pattern}
				);
			}
			else
			{
				selectSignaturesWithNames(
						allSigs,
						vsSigsSpecific,
						{arch, archSize, format, pattern}
				);
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
			selectSignaturesWithNames(
					allSigs,
					sigs,
					{arch, archSize, format, "mingw-4.7.3"}
			);
		}
		else if (c.tools.isTool("4.4.0"))
		{
			selectSignaturesWithNames(
					allSigs,
					sigs,
					{arch, archSize, format, "mingw-4.4.0"}
			);
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
					{arch, archSize, format, "psp-gcc-4.3.5"},
					{"pic32", "uClibc"});
		}
		else if (c.tools.isPic32()
				&& c.tools.isTool("4.5.2"))
		{
			selectSignaturesWithNames(
					allSigs,
					sigs,
					{arch, archSize, format, "pic32-gcc-4.5.2"},
					{"psp", "uClibc"});
		}
		else if (c.fileFormat.isPe())
		{
			if (c.tools.isTool("4.7.3"))
			{
				selectSignaturesWithNames(
						allSigs,
						sigs,
						{arch, archSize, format, "mingw-4.7.3"}
				);
			}
			else if (c.tools.isTool("4.4.0"))
			{
				selectSignaturesWithNames(
						allSigs,
						sigs,
						{arch, archSize, format, "mingw-4.4.0"}
				);
			}
		}
		else // if (c.tools.isGcc())
		{
			if (c.tools.isTool("4.8.3"))
			{
				selectSignaturesWithNames(
						allSigs,
						sigs,
						{arch, archSize, format, "gcc-4.8.3"},
						{"psp", "pic32", "uClibc"});
			}
			else if (c.tools.isTool("4.7.2"))
			{
				selectSignaturesWithNames(
						allSigs,
						sigs,
						{arch, archSize, format, "gcc-4.7.2"},
						{"psp", "pic32", "uClibc"});
			}
			else if (c.tools.isTool("4.4.1"))
			{
				selectSignaturesWithNames(
						allSigs,
						sigs,
						{arch, archSize, format, "gcc-4.4.1"},
						{"psp", "pic32", "uClibc"});
			}
			else if (c.tools.isTool("4.5.2"))
			{
				selectSignaturesWithNames(
						allSigs,
						sigs,
						{arch, archSize, format, "gcc-4.5.2"},
						{"psp", "pic32", "uClibc"});
			}
		}
	}

	if (c.fileFormat.isIntelHex() || c.fileFormat.isRaw())
	{
		if (c.architecture.isMips())
		{
			selectSignaturesWithNames(
					allSigs,
					sigs,
					{"elf", archSize, "mips", "psp-gcc"},
					{"uClibc"}
			);
		}
		if (c.architecture.isPic32())
		{
			selectSignaturesWithNames(
					allSigs,
					sigs,
					{"elf", archSize, "mips", "pic32-gcc"},
					{"uClibc"}
			);
		}
	}

	if (c.tools.isDelphi())
	{
		selectSignaturesWithNames(
				allSigs,
				sigs,
				{"pe", archSize, "delphi", "kb7"}
		);
	}

	return sigs;
}

void collectImports(
		const retdec::loader::Image* image,
		std::map<common::Address, std::string>& imports)
{
	LOG << "\t collectImports():" << std::endl;

	if (auto* impTbl = image->getFileFormat()->getImportTable())
	for (const auto &imp : *impTbl)
	{
		retdec::common::Address addr = imp->getAddress();
		if (addr.isUndefined())
		{
			continue;
		}

		imports.emplace(addr, imp->getName());
		LOG << "\t\t" << addr << " @ " << imp->getName() << std::endl;
	}
}

std::string dumpDetectedFunctions(
		stacofin::Finder& codeFinder,
		const retdec::loader::Image* image)
{
	std::stringstream ret;
	ret << "\t Detected functions (stacofin):" << "\n";
	for (auto& p : codeFinder.getAllDetections())
	{
		auto& f = p.second;
		ret << "\t\t" << f.getAddress() << " @ " << f.names.front()
				<< ", sz = " << f.size << ", from = " << f.signaturePath
				<< "\n";

		for (auto& p : f.references)
		{
			ret << "\t\t\t" << p.address << " @ " << p.name << "\n";
		}
	}

	return ret.str();
}

std::string dumpDetectedFunctions(
		const retdec::stacofin::DetectedFunctionsMultimap& allDetections)
{
	std::stringstream ret;
	ret << "\t Detected functions (bin2llvmir):" << "\n";
	for (auto& p : allDetections)
	{
		auto& f = p.second;

		ret << "\t\t" << (p.second.allRefsOk() ? "[+] " : "[-] ")
				<< f.getAddress() << " @ " << f.names.front()
				<< ", sz = " << f.size << "\n";

		for (auto& ref : f.references)
		{
			ret << "\t\t\t" << (ref.ok ? "[+] " : "[-] ")
					<< ref.address << " @ " << ref.name
					<< " -> " << ref.target << "\n";
		}
	}

	return ret.str();
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
		common::Address a,
		common::Address t,
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

	for (;;)
	{
		refsStream >> std::hex >> offset;
		refsStream >> name;
		if (!refsStream)
		{
			break;
		}

		references.push_back({offset, name});
	}
}

/**
 * Setting an address will also fix addresses of all the function's references.
 */
void DetectedFunction::setAddress(retdec::common::Address a)
{
	address = a;
	for (auto& r : references)
	{
		r.address = r.offset + a;
	}
}

retdec::common::Address DetectedFunction::getAddress() const
{
	return address;
}

//
//==============================================================================
// Finder.
//==============================================================================
//

/**
 * Return detected code coverage.
 *
 * @return covered code
 */
CoveredCode Finder::getCoveredCode()
{
	return coveredCode;
}

const DetectedFunctionsMultimap& Finder::getAllDetections() const
{
	return _allDetections;
}

const DetectedFunctionsPtrMap& Finder::getConfirmedDetections() const
{
	return _confirmedDetections;
}

/**
 * Search for static code in input file.
 *
 * @param image input file image
 * @param yaraFile static code signature file
 */
void Finder::search(
	const Image& image,
	const std::string& yaraFile)
{
	// Get FileFormat instance.
	const auto* fileFormat = image.getFileFormat();
	if (!fileFormat)
	{
		return;
	}

	// Start Yara detector.
	YaraDetector detector;
	detector.addRuleFile(yaraFile);
	auto inputBytes = fileFormat->getLoadedBytes();
	detector.analyze(inputBytes);
	if (!detector.isInValidState())
	{
		return;
	}

	// Iterate over detected rules.
	for (const YaraRule &detectedRule : detector.getDetectedRules())
	{
		DetectedFunction detectedFunction;
		detectedFunction.signaturePath = yaraFile;

		for (const YaraMeta &ruleMeta : detectedRule.getMetas())
		{
			if (ruleMeta.getId() == "name")
			{
				detectedFunction.names.push_back(ruleMeta.getStringValue());
			}
			if (ruleMeta.getId() == "size")
			{
				detectedFunction.size = ruleMeta.getIntValue();
			}
			if (ruleMeta.getId() == "refs")
			{
				const auto &refs = ruleMeta.getStringValue();
				detectedFunction.setReferences(refs);
			}
			if (ruleMeta.getId() == "altNames")
			{
				std::string name;
				const auto &altNames = ruleMeta.getStringValue();
				std::istringstream ss(altNames, std::istringstream::in);
				while(ss >> name)
				{
					detectedFunction.names.push_back(name);
				}
			}
		}

		// Iterate over all matches.
		for (const YaraMatch &ruleMatch : detectedRule.getMatches())
		{
			// This is different for every match.
			detectedFunction.offset = ruleMatch.getOffset();
			std::uint64_t address = 0;
			if (!fileFormat->getAddressFromOffset(
						address, detectedFunction.offset))
			{
				// Cannot get address. Maybe report error?
				continue;
			}

			// Store data.
			detectedFunction.setAddress(address);
			coveredCode.insert(AddressRange(
					address,
					address + detectedFunction.size));

			_allDetections.emplace(detectedFunction.getAddress(), detectedFunction);
		}
	}
}

/**
 * Search for static code in input file.
 *
 * @param image input file image
 * @param yaraFiles static code signature files
 */
void Finder::search(
	const retdec::loader::Image& image,
	const std::set<std::string>& yaraFiles)
{
	for (const auto& f : yaraFiles)
	{
		search(image, f);
	}
}

/**
 * Search for static code in input file based on information in config file.
 *
 * @param image input file image
 * @param config config file
 */
void Finder::search(
	const retdec::loader::Image& image,
	const retdec::config::Config& config)
{
	auto sigPaths = selectSignaturePaths(image, config);
	search(image, sigPaths);
}

void Finder::searchAndConfirm(
		const retdec::loader::Image& image,
		const retdec::config::Config& config)
{
	search(image, config);

	_config = &config;
	_image = &image;

	if (initDisassembler() || _ceInsn == nullptr)
	{
		return;
	}

	LOG << "\n StaticCodeAnalysis():" << std::endl;

	LOG << dumpDetectedFunctions(*this, _image) << std::endl;

	collectImports(_image, _imports);
	for (auto& s : _image->getSegments())
	{
		if (!s->getName().empty())
		{
			_sectionNames.emplace(s->getName());
		}
	}

	LOG << dumpDetectedFunctions(_allDetections) << std::endl;
	solveReferences();
	LOG << dumpDetectedFunctions(_allDetections) << std::endl;

	for (auto& p : _allDetections)
	{
		_worklistDetections.insert(&p.second);
	}

	confirmWithoutRefs();
	confirmAllRefsOk();
	confirmPartialRefsOk();

	LOG << "\t Confirmed detections:" << std::endl;
	for (auto& p : _confirmedDetections)
	{
		LOG << "        " << "assert self.out_config.is_statically_linked('"
				<< p.second->getName() << "', " << p.first << ")"
				<< std::endl;
	}
	LOG << "\t Rejected detections:" << std::endl;
	for (auto& p : _rejectedDetections)
	{
		LOG << "        " << "assert not self.out_config.is_statically_linked('"
				<< p.second->getName() << "', " << p.first << ")"
				<< std::endl;
	}
	LOG << "\t Worklist detections:" << std::endl;
	for (auto* f : _worklistDetections)
	{
		LOG << "        " << "assert not self.out_config.is_statically_linked('"
				<< f->getName() << "', " << f->getAddress() << ")"
				<< std::endl;
	}

	cs_free(_ceInsn, 1);
	cs_close(&_ce);
}

/**
 * @return @c False of everything ok, @c true otherwise.
 */
bool Finder::initDisassembler()
{
	cs_arch arch;
	_ceMode = CS_MODE_LITTLE_ENDIAN;
	if (_config->architecture.isX86())
	{
		arch = CS_ARCH_X86;
		_ceMode = CS_MODE_32;
	}
	else if (_config->architecture.isMipsOrPic32())
	{
		arch = CS_ARCH_MIPS;
		_ceMode = CS_MODE_MIPS32;
	}
	else if (_config->architecture.isArm32OrThumb())
	{
		arch = CS_ARCH_ARM;
		_ceMode = CS_MODE_ARM;
	}
	else if (_config->architecture.isPpc())
	{
		arch = CS_ARCH_PPC;
		_ceMode = CS_MODE_LITTLE_ENDIAN;
	}
	else
	{
		return true;
	}

	if (cs_open(arch, _ceMode, &_ce) != CS_ERR_OK)
	{
		return true;
	}
	if (cs_option(_ce, CS_OPT_DETAIL, CS_OPT_ON) != CS_ERR_OK)
	{
		return true;
	}
	_ceInsn = cs_malloc(_ce);

	return false;
}

void Finder::solveReferences()
{
	for (auto& p : _allDetections)
	{
		bool modeSwitch = false;
		std::string& sigPath = p.second.signaturePath;
		if (_config->architecture.isArm32OrThumb()
				&& utils::containsCaseInsensitive(sigPath, "thumb"))
		{
			if (cs_option(_ce, CS_OPT_MODE, CS_MODE_THUMB) != CS_ERR_OK)
			{
				assert(false);
				return;
			}
			modeSwitch = true;
		}

		for (auto& r : p.second.references)
		{
			r.target = getAddressFromRef(r.address);
			checkRef(r);
		}

		if (modeSwitch)
		{
			if (cs_option(_ce, CS_OPT_MODE, _ceMode) != CS_ERR_OK)
			{
				assert(false);
				return;
			}
		}
	}
}

common::Address Finder::getAddressFromRef(common::Address ref)
{
	if (_config->architecture.isX86())
	{
		return getAddressFromRef_x86(ref);
	}
	else if (_config->architecture.isMipsOrPic32())
	{
		return getAddressFromRef_mips(ref);
	}
	else if (_config->architecture.isArm())
	{
		return getAddressFromRef_arm(ref);
	}
	else if (_config->architecture.isPpc())
	{
		return getAddressFromRef_ppc(ref);
	}
	else
	{
		assert(false);
		return Address();
	}
}

common::Address Finder::getAddressFromRef_x86(common::Address ref)
{
	uint64_t val = 0;
	if (!_image->getWord(ref, val))
	{
		return Address();
	}

	Address absAddr = val;
	Address addrAfterRef = ref + _image->getBytesPerWord();
	Address relAddr = addrAfterRef + int32_t(val);

	auto imgBase = _image->getBaseAddress();
	if (absAddr == imgBase)
	{
		return absAddr;
	}
	else if (relAddr == imgBase)
	{
		return relAddr;
	}

	bool absOk = _image->hasDataOnAddress(absAddr);
	bool relOk = _image->hasDataOnAddress(relAddr);

	if (absOk && !relOk)
	{
		return absAddr;
	}
	else if (!absOk && relOk)
	{
		return relAddr;
	}
	else if (absOk && relOk)
	{
		// both ok, what now? prefer absolute address.
		return absAddr;
	}
	else
	{
		// default
		return absAddr;
	}

	return Address();
}

bool isJumpInsn_mips(csh ce, cs_insn* i)
{
	// For whatever reason, this does not work very well (at all?).
	// e.g. jal 0x8905b28 is only in one group: 137 (stdenc)
	//
	if (cs_insn_group(ce, i, MIPS_GRP_JUMP)
			|| cs_insn_group(ce, i, MIPS_GRP_CALL))
	{
		return true;
	}

	switch (i->id)
	{
		case MIPS_INS_J:
		case MIPS_INS_JAL:
			return true;
		default:
			return false;
	}
}

bool isLoadStoreInsn_mips(csh ce, cs_insn* i)
{
	switch (i->id)
	{
		// Load.
		case MIPS_INS_LB:
		case MIPS_INS_LBU:
		case MIPS_INS_LH:
		case MIPS_INS_LHU:
		case MIPS_INS_LW:
		case MIPS_INS_LWU:
		case MIPS_INS_LD:
		case MIPS_INS_LDC3:
		case MIPS_INS_LWC1:
		case MIPS_INS_LDC1:
		// Store
		case MIPS_INS_SB:
		case MIPS_INS_SH:
		case MIPS_INS_SW:
		case MIPS_INS_SD:
		case MIPS_INS_SDC3:
		case MIPS_INS_SWC1:
		case MIPS_INS_SDC1:
			return true;
		default:
			return false;
	}
}

bool isAddInsn_mips(csh ce, cs_insn* i)
{
	switch (i->id)
	{
		case MIPS_INS_ADDI:
		case MIPS_INS_ADDIU:
		case MIPS_INS_ADD:
		case MIPS_INS_ADDU:
			return true;
		default:
			return false;
	}
}

/**
 * On MIPS, reference is an instruction that needs to be disassembled and
 * inspected for reference target.
 */
common::Address Finder::getAddressFromRef_mips(common::Address ref)
{
	uint64_t addr = ref;
	ByteData data = _image->getRawSegmentData(ref);
	if (!cs_disasm_iter(_ce, &data.first, &data.second, &addr, _ceInsn))
	{
		return Address();
	}
	auto& mips = _ceInsn->detail->mips;

	// j target_function
	// jal target_function
	//
	if (isJumpInsn_mips(_ce, _ceInsn)
			&& mips.op_count == 1
			&& mips.operands[0].type == MIPS_OP_IMM)
	{
		return mips.operands[0].imm;
	}
	// lui reg, upper
	// ...
	//
	else if (_ceInsn->id == MIPS_INS_LUI
			&& mips.op_count == 2
			&& mips.operands[0].type == MIPS_OP_REG
			&& mips.operands[1].type == MIPS_OP_IMM)
	{
		auto reg = mips.operands[0].reg;
		unsigned s = _config->architecture.getBitSize() / 2;
		uint64_t upper = uint64_t(mips.operands[1].imm) << s;

		if (!cs_disasm_iter(_ce, &data.first, &data.second, &addr, _ceInsn))
		{
			return Address();
		}

		// Sometimes, the other instruction is not right after the LUI.
		// Try to disassemble one more.
		// Maybe, we should check that skipped instruction does not use reg.
		// Maybe, more than one instruction needs to be skipped.
		//
		if (!isLoadStoreInsn_mips(_ce, _ceInsn)
				&& !isAddInsn_mips(_ce, _ceInsn))
		{
			if (!cs_disasm_iter(_ce, &data.first, &data.second, &addr, _ceInsn))
			{
				return Address();
			}
		}

		// lui $a0, 0x891
		// lw $a0, 0x7b68($a0)
		// ==> 0x891 7B68
		//
		// lui $at, 0x892
		// sw $zero, -0x1f14($at)
		// ==> 0x891 E0EC
		//
		if (isLoadStoreInsn_mips(_ce, _ceInsn)
				&& mips.op_count == 2
				&& mips.operands[1].type == MIPS_OP_MEM
				&& mips.operands[1].mem.base == reg)
		{
			Address t = upper + mips.operands[1].mem.disp;
			return t;
		}
		// lui $a2, 0x891
		// addiu $a2, $a2, 0x5ff4
		// ==> 0x891 5FF4
		//
		else if (isAddInsn_mips(_ce, _ceInsn)
				&& mips.op_count == 3
				&& mips.operands[1].type == MIPS_OP_REG
				&& mips.operands[1].reg == reg
				&& mips.operands[2].type == MIPS_OP_IMM)
		{
			Address t = upper +  mips.operands[2].imm;
			return t;
		}
	}

	return Address();
}

/**
 * On ARM, reference may be an instruction that needs to be disassembled and
 * inspected for reference target,
 * or
 * a word after the function that just needs to be read (it should point
 * somewhere to the loaded image, but that is checked later).
 */
common::Address Finder::getAddressFromRef_arm(common::Address ref)
{
	std::uint64_t ci = 0;
	if (_image->getWord(ref, ci))
	{
		// If word reference looks ok, use it.
		//
		if (ci == _image->getBaseAddress())
		{
			return ci;
		}
		else if (_allDetections.count(ci))
		{
			return ci;
		}
		else if (ci % 2 && _allDetections.count(ci - 1))
		{
			return ci - 1;
		}
	}
	else
	{
		// problem
		ci = 0;
	}

	// Try to disassemble the reference data into instruction.
	//
	uint64_t addr = ref;
	ByteData data = _image->getRawSegmentData(ref);
	if (cs_disasm_iter(_ce, &data.first, &data.second, &addr, _ceInsn))
	{
		auto& arm = _ceInsn->detail->arm;

		bool isBr = cs_insn_group(_ce, _ceInsn, ARM_GRP_JUMP)
				|| cs_insn_group(_ce, _ceInsn, ARM_GRP_CALL)
				|| cs_insn_group(_ce, _ceInsn, ARM_GRP_BRANCH_RELATIVE);

		if (isBr
				&& arm.op_count == 1
				&& arm.operands[0].type == ARM_OP_IMM
				&& _image->hasDataOnAddress(arm.operands[0].imm))
		{
			auto val = arm.operands[0].imm;
			val = val%2 ? val-1 : val;
			return val;
		}
		// bx lr
		//
		else if (isBr
				&& arm.op_count == 1
				&& arm.operands[0].type == ARM_OP_REG)
		{
			return Address();
		}
		// mov pc, lr (return)
		//
		else if (_ceInsn->id == ARM_INS_MOV
				&& arm.op_count == 2
				&& arm.operands[0].type == ARM_OP_REG
				&& arm.operands[0].reg == ARM_REG_PC
				&& arm.operands[1].type == ARM_OP_REG
				&& arm.operands[1].reg == ARM_REG_LR)
		{
			return Address();
		}
	}

	// If we get here and reference word exists, always use reference.
	//
	if (ci)
	{
		return ci;
	}

	return Address();
}

common::Address Finder::getAddressFromRef_ppc(common::Address ref)
{
	std::uint64_t ci = 0;
	if (_image->getWord(ref, ci))
	{
		// If word reference looks ok, use it.
		//
		if (ci == _image->getBaseAddress())
		{
			return ci;
		}
		else if (ci && _allDetections.count(ci))
		{
			return ci;
		}
	}
	else
	{
		ci = 0;
	}

	// Try to disassemble the reference data into instruction.
	//
	uint64_t addr = ref;
	ByteData data = _image->getRawSegmentData(ref);
	if (cs_disasm_iter(_ce, &data.first, &data.second, &addr, _ceInsn))
	{
		auto& ppc = _ceInsn->detail->ppc;

		if (_ceInsn->id == PPC_INS_BL
				&& ppc.op_count == 1
				&& ppc.operands[0].type == PPC_OP_IMM)
		{
			return ppc.operands[0].imm;
		}
	}

	// If we get here and reference word exists, always use reference.
	//
	if (ci)
	{
		return ci;
	}
	return Address();
}

void Finder::checkRef(Reference& ref)
{
	if (ref.target.isUndefined())
	{
		return;
	}

	// TODO: make sure references do not point into detected function body
	// of the source function. e.g. reference to detected function does
	// not overlap with the original function.

	// Reference to detected function.
	//
	auto dIt = _allDetections.equal_range(ref.target);
	if (dIt.first != dIt.second)
	{
		for (auto it = dIt.first, e = dIt.second; it != e; ++it)
		{
			if (hasItem(it->second.names, ref.name))
			{
				ref.targetFnc = &it->second;
				ref.ok = true;
			}
		}

		return;
	}

	// Reference to import.
	//
	auto fIt = _imports.find(ref.target);
	if (fIt != _imports.end())
	{
		if (utils::contains(fIt->second, ref.name)
				|| utils::contains(ref.name, fIt->second))
		{
			ref.ok = true;
		}

		return;
	}

	// Reference to image base.
	//
	if (ref.target == _image->getBaseAddress()
			&& ref.name == "__image_base__")
	{
		ref.ok = true;
		return;
	}

	// Reference into section with reference name equal to section name.
	// PIC32 may reference a function which is not detected as statically
	// linked, but which has its own section named '.text.<refName>'
	//
	auto* seg = _image->getSegmentFromAddress(ref.target);
	if (seg
			&& utils::contains(seg->getName(), ref.name)
			// Otherwise, this would hit even general reference like ".text".
			&& utils::startsWith(seg->getName(), ".text."))
	{
		ref.ok = true;
		return;
	}

	// Architecture specific ckecks.
	//
	if (_config->architecture.isX86())
	{
		checkRef_x86(ref);
	}
	if (ref.ok)
	{
		return;
	}

	// There is no info in reference about what it is referencing (function,
	// data object, whole section via its name, etc.).
	// If reference name is an existing section name, but it is not the name of
	// section where reference target is, reference is no good.
	// Otherwise, the following check would for example hit reference with name
	// ".bss" in section ".rodata".
	//
	auto secNameIt = _sectionNames.find(ref.name);
	if (secNameIt != _sectionNames.end()
			&& seg && seg->getName() != ref.name)
	{
		return;
	}
	auto* sec = seg ? seg->getSecSeg() : nullptr;
	if (sec)
	{
		if (ref.name == ".bss" && !sec->isBss()) return;
		if (ref.name == ".rodata" && !sec->isReadOnly()) return;
		if (ref.name == ".data" && !sec->isData()) return;
		// other ...?
	}

	// Reference into section with reference name set to some object name.
	// This must be the last check, because it can hit anything.
	//
	if (sec
			&& (sec->getType() == fileformat::SecSeg::Type::DATA
// Disabled because we can not distinguish between functions and data objects.
// We would like to hit data objects even in CODE section.
// But this could also falsely hit missing functions - e.g. we expect
// statically linked function on some address, but do not find it there,
// the first check in this list fails, but this will still succeed.
//					|| sec->getType() == fileformat::SecSeg::Type::CODE
					|| sec->getType() == fileformat::SecSeg::Type::CODE_DATA
					|| sec->getType() == fileformat::SecSeg::Type::CONST_DATA
					|| sec->getType() == fileformat::SecSeg::Type::BSS))
	{
		ref.ok = true;
		return;
	}

	// Reference to one byte after some section.
	// e.g. ___RUNTIME_PSEUDO_RELOC_LIST_END__ on x86 after .rdata
	//
	if (seg == nullptr
			&& _image->getSegmentFromAddress(ref.target-1))
	{
		ref.ok = true;
		return;
	}
}

void Finder::checkRef_x86(Reference& ref)
{
	if (ref.target.isUndefined())
	{
		return;
	}

	uint64_t addr = ref.target;
	ByteData bytes = _image->getRawSegmentData(ref.target);
	if (cs_disasm_iter(_ce, &bytes.first, &bytes.second, &addr, _ceInsn))
	{
		auto& x86 = _ceInsn->detail->x86;

		// Pattern: reference to stub function jumping to import:
		//     _localeconv     proc near
		//     FF 25 E0 B1 40 00        jmp ds:__imp__localeconv
		//     _localeconv     endp
		//
		if (_ceInsn->id == X86_INS_JMP
				&& x86.op_count == 1
				&& x86.operands[0].type == X86_OP_MEM
				&& x86.operands[0].mem.segment == X86_REG_INVALID
				&& x86.operands[0].mem.base == X86_REG_INVALID
				&& x86.operands[0].mem.index == X86_REG_INVALID
				&& x86.operands[0].mem.scale == 1
				&& x86.operands[0].mem.disp)
		{
			auto fIt = _imports.find(x86.operands[0].mem.disp);
			if (fIt != _imports.end())
			{
				if (utils::contains(fIt->second, ref.name)
						|| utils::contains(ref.name, fIt->second))
				{
					ref.ok = true;
				}

				return;
			}
		}
	}
}

/**
 * Sometimes, we don't need references to solve detections.
 * e.g. on PIC32 detected function '_scanf_cdnopuxX' is in section
 * `.text._scanf_cdnopuxX`.
 * Sort detected functions.
 *
 * Functions are sorted by their address, if detection address is same bigger
 * detection is first.
 */
void Finder::confirmWithoutRefs()
{
	LOG << "\t" << "confirmWithoutRefs()" << std::endl;

	auto worklistCopy = _worklistDetections;
	for (auto* f : worklistCopy)
	{
		if (_worklistDetections.count(f) == 0)
		{
			continue;
		}

		if (auto* s = _image->getSegmentFromAddress(f->getAddress()))
		{
			for (auto& n : f->names)
			{
				if (s->getName() == (".text." + n))
				{
					confirmFunction(f);
					break;
				}
			}
		}
	}
}

struct comByRefSizeAddress
{
	bool operator() (
			const DetectedFunction* lhs,
			const DetectedFunction* rhs) const
	{
		if (lhs->references.size() == rhs->references.size())
		{
			if (lhs->size == rhs->size)
			{
				return lhs->getAddress() > rhs->getAddress();
			}
			else
			{
				return lhs->size > rhs->size;
			}
		}
		else
		{
			return lhs->references.size() > rhs->references.size();
		}
	}
};

void Finder::confirmAllRefsOk(std::size_t minFncSzWithoutRefs)
{
	LOG << "\t" << "confirmAllRefsOk()" << std::endl;

	// Sort all functions with all references OK by number of references
	// (and other stuff).
	//
	std::multiset<DetectedFunction*, comByRefSizeAddress> byRefNum;

	DetectedFunctionsPtrMultimap byAddress;
	for (auto* f : _worklistDetections)
	{
		if (f->allRefsOk())
		{
			byRefNum.insert(f);
			byAddress.emplace(f->getAddress(), f);
		}
	}
	LOG << "\t\t" << "byRefNum (sz = " << byRefNum.size() << "):" << std::endl;
	for (auto& f : byRefNum)
	{
		LOG << "\t\t\t" << f->references.size() << " @ " << f->getAddress()
				<< " " << f->getName() << ", sz = " << f->size << std::endl;
	}

	// From functions with the most references to those with at least one
	// reference, confirm function if:
	//   - No conflicting function at the same address.
	//   - Conflicting function is shorter or has less references.
	//   - Function has at least some reference or is not too short.
	//
	for (auto* f : byRefNum)
	{
		// Function was solved in the meantime.
		//
		if (_worklistDetections.count(f) == 0)
		{
			continue;
		}

		// Skip functions without references that are to short.
		//
		if (f->references.empty() && f->size < minFncSzWithoutRefs)
		{
			continue;
		}

		// Only one function at this address.
		//
		if (byAddress.count(f->getAddress()) == 1)
		{
			confirmFunction(f);
		}

		//
		//
		bool bestConflicting = true;
		auto eqr = byAddress.equal_range(f->getAddress());
		for (auto it = eqr.first; it != eqr.second; ++it)
		{
			auto* of = it->second;
			if (f != of)
			{
				if (!(f->size > of->size
						|| f->references.size() > of->references.size()))
				{
					bestConflicting = false;
					break;
				}
			}
		}
		if (bestConflicting)
		{
			confirmFunction(f);
		}
	}
}

void Finder::confirmPartialRefsOk(float okShare)
{
	LOG << "\t" << "confirmPartialRefsOk()" << std::endl;

	while (true)
	{
		// Find the function with max ok share.
		//
		float maxShare = 0.0;
		DetectedFunction* f = nullptr;
		for (auto* of : _worklistDetections)
		{
			if (of->references.empty())
			{
				continue;
			}

			float ms = of->refsOkShare();
			if (ms > maxShare
					|| (ms == maxShare && f && of->size > f->size))
			{
				maxShare = ms;
				f = of;
			}
		}

		// Check if share ok.
		//
		if (f == nullptr || maxShare < okShare)
		{
			break;
		}
		LOG << "\t\t" << "[" << maxShare << "] " << f->getAddress()
				<< " @ " << f->getName() << std::endl;

		// This can increase ok share in other function by confirming all
		// (even unsolved) references in this function -> repeat loop.
		//
		confirmFunction(f);
	}
}

void Finder::confirmFunction(DetectedFunction* f)
{
	LOG << "\t\t" << "confirming " << f->getName() << " @ " << f->getAddress()
			<< std::endl;

	// Confirm the function.
	//
	_confirmedDetections.emplace(f->getAddress(), f);
	_worklistDetections.erase(f);

	// Reject all other function at the same address.
	//
	auto eqr = _allDetections.equal_range(f->getAddress());
	for (auto it = eqr.first; it != eqr.second; ++it)
	{
		auto* of = &it->second;
		if (of != f)
		{
			_rejectedDetections.emplace(of->getAddress(), of);
			_worklistDetections.erase(of);
			LOG << "\t\t\t" << "rejecting #1 " << of->getName() << " @ "
					<< of->getAddress() << std::endl;
		}
	}

	// Reject all functions that overlap with the function.
	//
	AddressRange range(f->getAddress(), f->getAddress() + f->size);
	auto it = _worklistDetections.begin(), e = _worklistDetections.end();
	while (it != e)
	{
		auto* of = *it;
		if (of != f)
		{
			AddressRange oRange(of->getAddress(), of->getAddress() + of->size);
			if (range.overlaps(oRange))
			{
				_rejectedDetections.emplace(of->getAddress(), of);
				it = _worklistDetections.erase(it);
				LOG << "\t\t\t" << "rejecting #2 " << of->getName() << " @ "
						<< of->getAddress() << std::endl;
				continue;
			}
		}
		++it;
	}

	// Confirm and make use of all references.
	//
	for (auto& r : f->references)
	{
		// Confirm all functions referenced from the function.
		//
		if (r.targetFnc && _worklistDetections.count(r.targetFnc))
		{
			confirmFunction(r.targetFnc);
		}

		// Confirm this reference in all detected functions.
		//
		if (!r.ok)
		{
			for (auto& p : _allDetections)
			for (auto& oref : p.second.references)
			{
				if (r.target == oref.target && r.name == oref.name)
				{
					oref.ok = true;
				}
			}
		}
	}
}

} // namespace stacofin
} // namespace retdec
