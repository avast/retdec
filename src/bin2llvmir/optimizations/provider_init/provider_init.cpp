/**
 * @file src/bin2llvmir/optimizations/provider_init/provider_init.cpp
 * @brief One time providers initialization.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <regex>

#include <llvm/Support/CommandLine.h>

#include "retdec/utils/io/log.h"
#include "retdec/bin2llvmir/analyses/symbolic_tree.h"
#include "retdec/bin2llvmir/optimizations/provider_init/provider_init.h"
#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/providers/calling_convention/calling_convention.h"
#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/providers/debugformat.h"
#include "retdec/bin2llvmir/providers/demangler.h"
#include "retdec/bin2llvmir/providers/fileimage.h"
#include "retdec/bin2llvmir/providers/lti.h"
#include "retdec/bin2llvmir/providers/names.h"
#include "retdec/cpdetect/cpdetect.h"
#include "retdec/utils/string.h"
#include "retdec/yaracpp/yara_detector.h"

using namespace llvm;
using namespace retdec::utils::io;

namespace retdec {
namespace bin2llvmir {

common::Pattern saveCryptoRule(
		const yaracpp::YaraRule &rule,
		retdec::fileformat::FileFormat* file)
{
	const auto name = rule.getName();
	auto pattern = common::Pattern::crypto(name, "", name);
	const auto *descMeta = rule.getMeta("description");
	if(!descMeta)
	{
		descMeta = rule.getMeta("desc");
	}
	pattern.setDescription(descMeta ? descMeta->getStringValue() : name);
	std::smatch rMatch, rMatchFlt;
	bool isInt = false, isFlt = false, entrySize = false;
	if(regex_search(name, rMatch, std::regex("__([0-9]+)_(big|lil|byt)_")))
	{
		entrySize = true;
		if(rMatch[2] == "lil")
		{
			pattern.setIsEndianLittle();
		}
		else if(rMatch[2] == "big")
		{
			pattern.setIsEndianBig();
		}

		if(regex_search(name, rMatchFlt, std::regex("__flt([0-9]+)___")))
		{
			isFlt = true;
			pattern.setName(rMatchFlt.prefix());
			if(!descMeta)
			{
				pattern.setDescription(rMatchFlt.prefix());
			}
		}
		else
		{
			isInt = true;
			pattern.setName(rMatch.prefix());
			if(!descMeta)
			{
				pattern.setDescription(rMatch.prefix());
			}
		}
	}

	std::string descInfo;
	unsigned long long entrySizeValue = 0;
	if(entrySize
			&& rMatch.size() > 1
			&& utils::strToNum(rMatch[1], entrySizeValue, std::dec))
	{
		descInfo.push_back('(');
		descInfo += rMatch[1];
		descInfo += "-bit";
	}
	else
	{
		entrySize = false;
	}

	if(pattern.isEndianLittle() || pattern.isEndianBig())
	{
		if(descInfo.empty())
		{
			descInfo.push_back('(');
		}
		else
		{
			descInfo += ", ";
		}
		descInfo += (pattern.isEndianLittle() ? "little" : "big");
		descInfo += " endian";
	}

	if(!descInfo.empty())
	{
		if(descInfo[0] == '(')
		{
			descInfo.push_back(')');
		}
		pattern.setDescription(pattern.getDescription() + " " + descInfo);
	}

	for(std::size_t i = 0, e = rule.getNumberOfMatches(); i < e; ++i)
	{
		const auto *match = rule.getMatch(i);
		if(!match)
		{
			continue;
		}
		common::Pattern::Match patMatch;
		if(isFlt)
		{
			patMatch.setIsTypeFloatingPoint();
		}
		else if(isInt)
		{
			patMatch.setIsTypeIntegral();
		}
		patMatch.setSize(match->getDataSize());

		if(entrySize)
		{
			patMatch.setEntrySize(entrySizeValue / file->getByteLength());
		}
		patMatch.setOffset(match->getOffset());
		std::uint64_t val = 0;
		if(file->getAddressFromOffset(val, match->getOffset()))
		{
			patMatch.setAddress(val);
		}
		pattern.matches.push_back(patMatch);
	}

	return pattern;
}

char ProviderInitialization::ID = 0;

static RegisterPass<ProviderInitialization> X(
		"retdec-provider-init",
		"Providers initialization",
		 false, // Only looks at CFG
		 false // Analysis Pass
);

ProviderInitialization::ProviderInitialization(retdec::config::Config* c) :
		ModulePass(ID)
{
	setConfig(c);
}

void ProviderInitialization::setConfig(retdec::config::Config* c)
{
	_config = c;
}

/**
 * @return Always @c false -- this pass does not modify module.
 */
bool ProviderInitialization::runOnModule(Module& m)
{
	AbiProvider::clear();
	AsmInstruction::clear();
	ConfigProvider::clear();
	DebugFormatProvider::clear();
	DemanglerProvider::clear();
	FileImageProvider::clear();
	LtiProvider::clear();
	NamesProvider::clear();
	SymbolicTree::clear();
	CallingConventionProvider::clear();

	// Config.
	//
	Config* c = nullptr;
	if (_config)
	{
		c = ConfigProvider::addConfig(&m, *_config);
	}

	if (c == nullptr)
	{
		throw std::runtime_error("ProviderInitialization: c == nullptr");
	}

	// Fileimage.
	//
	auto* f = FileImageProvider::addFileImage(
			&m,
			c->getConfig().parameters.getInputFile(),
			c);
	if (f == nullptr)
	{
		throw std::runtime_error("ProviderInitialization: f == nullptr");
	}

	// Set config info from fileimage (it was not initialized by fileinfo).
	// TODO: refactor the whole thing around this.
	//
	auto& a = c->getConfig().architecture;
	if (a.isUnknown())
	{
		if (f->getFileFormat()->isLittleEndian())
		{
			a.setIsEndianLittle();
		}
		else if (f->getFileFormat()->isBigEndian())
		{
			a.setIsEndianBig();
		}

		a.setBitSize(f->getFileFormat()->getWordLength());

		switch (f->getFileFormat()->getTargetArchitecture())
		{
			case fileformat::Architecture::X86: a.setIsX86(); break;
			case fileformat::Architecture::X86_64: a.setIsX86(); break;
			case fileformat::Architecture::ARM: a.setIsArm(); break;
			case fileformat::Architecture::POWERPC: a.setIsPpc(); break;
			case fileformat::Architecture::MIPS: a.setIsMips(); break;
			default: break; // nothing
		}
	}
	auto& ff = c->getConfig().fileFormat;
	if (ff.isUnknown())
	{
		if (f->getFileFormat()->isElf()) ff.setIsElf();
		if (f->getFileFormat()->isPe()) ff.setIsPe();
		if (f->getFileFormat()->isCoff()) ff.setIsCoff();
		if (f->getFileFormat()->isIntelHex()) ff.setIsIntelHex();
		if (f->getFileFormat()->isMacho()) ff.setIsMacho();
		if (f->getFileFormat()->isRawData()) ff.setIsRaw();
		ff.setFileClassBits(f->getFileFormat()->getWordLength());
	}
	auto& ft = c->getConfig().fileType;
	if (ft.isUnknown())
	{
		if (f->getFileFormat()->isExecutable()) ft.setIsExecutable();
		if (f->getFileFormat()->isObjectFile()) ft.setIsObject();
		if (f->getFileFormat()->isDll()) ft.setIsShared();
	}
	std::uint64_t ep = 0;
	if (f->getFileFormat()->getEpAddress(ep))
	{
		c->getConfig().parameters.setEntryPoint(ep);
	}

	if ((f->getFileFormat()->getTargetArchitecture() == fileformat::Architecture::POWERPC
			|| f->getFileFormat()->getTargetArchitecture() == fileformat::Architecture::MIPS)
			&& f->getFileFormat()->getWordLength() == 64)
	{
		throw std::runtime_error("Unsupported target format and architecture combination");
	}

	// Run cpdetect and set info to config.
	// TODO: we could probably be using cpdetect results.
	//
	cpdetect::ToolInformation tools;
	cpdetect::DetectParams searchParams(
			cpdetect::SearchType::MOST_SIMILAR,
			true, // internal database
			false,
			50 // ep bytes size
	);
	cpdetect::CompilerDetector cd(
			*f->getFileFormat(),
			searchParams,
			tools
	);
	if (cd.getAllInformation() == cpdetect::ReturnCode::OK)
	{
		for (auto& t : tools.detectedTools)
		{
			common::ToolInfo ci;

			ci.setName(utils::toLower(t.name));
			switch (t.type)
			{
				case cpdetect::ToolType::COMPILER: ci.setType("compiler"); break;
				case cpdetect::ToolType::PACKER: ci.setType("packer"); break;
				case cpdetect::ToolType::INSTALLER: ci.setType("installer"); break;
				case cpdetect::ToolType::LINKER: ci.setType("linker"); break;
				case cpdetect::ToolType::OTHER: ci.setType("other tool"); break;
				case cpdetect::ToolType::UNKNOWN:
				default: ci.setType("unknown"); break;
			}
			ci.setVersion(utils::toLower(t.versionInfo));
			ci.setAdditionalInfo(t.additionalInfo);
			if(t.impCount)
			{
				ci.setPercentage(
						static_cast<double>(t.agreeCount) / t.impCount * 100
				);
			}
			else
			{
				ci.setPercentage(0.0);
			}
			ci.setIdenticalSignificantNibbles(t.agreeCount);
			ci.setTotalSignificantNibbles(t.impCount);

			bool similarityFlag = false;
			bool actualSimilarity;
			bool heuristics;
			if (t.source == cpdetect::DetectionMethod::SIGNATURE)
			{
				heuristics = false;
				actualSimilarity = (t.agreeCount != t.impCount);
				if(actualSimilarity)
				{
					if(similarityFlag)
					{
						continue;
					}
					similarityFlag = true;
				}
			}
			else
			{
				heuristics = true;
			}
			ci.setIsFromHeuristics(heuristics);

			c->getConfig().tools.push_back(ci);
		}
		for (auto& l : tools.detectedLanguages)
		{
			if (l.bytecode)
			{
				Log::error() << Log::Warning << "Detected " << l.name
						<< " bytecode, which cannot be decompiled by our "
						"machine-code decompiler. "
						"The decompilation result may be inaccurate.";
			}
		}
	}
	// TODO: this is needed, but we should remove the whole PIC thing.
	if (c->getConfig().tools.isPic32())
	{
		c->getConfig().architecture.setIsPic32();
	}

	// YARA crypto patterns scanning.
	//
	yaracpp::YaraDetector yara;
	for (auto& crypto : c->getConfig().parameters.cryptoPatternPaths)
	{
		yara.addRuleFile(crypto);
	}
	yara.analyze(c->getConfig().parameters.getInputFile());
	for(const auto &rule : yara.getDetectedRules())
	{
		common::Pattern p = saveCryptoRule(
				rule,
				f->getFileFormat()
		);
		c->getConfig().patterns.push_back(p);
	}
	// TODO: removeRedundantCryptoRules()
	// TODO: sortCryptoPatternMatches()

	// This can happen only after tools are detected.
	//
	f->initRtti(c);

	// ABI.
	//
	auto* abi = AbiProvider::addAbi(&m, c);
	SymbolicTree::setAbi(abi);
	SymbolicTree::setConfig(c);

	// maybe should be in config::Config
	auto typeConfig = std::make_shared<ctypesparser::TypeConfig>();

	auto* d = DemanglerProvider::addDemangler(&m, c, typeConfig);
	if (d == nullptr)
	{
		throw std::runtime_error("ProviderInitialization: d == nullptr");
	}

	auto* debug = DebugFormatProvider::addDebugFormat(
			&m,
			f->getImage(),
			c->getConfig().parameters.getInputPdbFile(),
			d
	);

	auto* lti = LtiProvider::addLti(&m, c, typeConfig, f->getImage());

	NamesProvider::addNames(&m, c, debug, f, d, lti);

	AsmInstruction::clear();

	return false;
}

/**
 * @return Always @c false -- this pass does not modify module.
 */
bool ProviderInitialization::doFinalization(Module& m)
{
	ConfigProvider::doFinalization(&m);
	return false;
}

} // namespace bin2llvmir
} // namespace retdec
