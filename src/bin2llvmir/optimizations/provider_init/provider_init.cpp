/**
 * @file src/bin2llvmir/optimizations/provider_init/provider_init.cpp
 * @brief One time providers initialization.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include <iostream>

#include <llvm/Support/CommandLine.h>

#include "retdec/bin2llvmir/analyses/symbolic_tree.h"
#include "retdec/bin2llvmir/optimizations/provider_init/provider_init.h"
#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/asm_instruction.h"
#include "retdec/bin2llvmir/providers/config.h"
#include "retdec/bin2llvmir/providers/debugformat.h"
#include "retdec/bin2llvmir/providers/demangler.h"
#include "retdec/bin2llvmir/providers/fileimage.h"
#include "retdec/bin2llvmir/providers/lti.h"
#include "retdec/bin2llvmir/providers/names.h"
#include "retdec/cpdetect/cpdetect.h"

using namespace llvm;

namespace retdec {
namespace bin2llvmir {

char ProviderInitialization::ID = 0;

static RegisterPass<ProviderInitialization> X(
		"provider-init",
		"Providers initialization",
		 false, // Only looks at CFG
		 false // Analysis Pass
);

cl::opt<std::string> ConfigPath(
		"config-path",
		cl::desc("Path to the config file."),
		cl::init("")
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
	static bool firstRun = true;
	if (!firstRun)
	{
		return false;
	}

	Config* c = nullptr;
	if (_config)
	{
		c = ConfigProvider::addConfig(&m, *_config);
	}
	else if (!ConfigPath.empty())
	{
		c = ConfigProvider::addConfigFile(&m, ConfigPath);
	}

	if (c == nullptr)
	{
		return false;
	}

	auto* f = FileImageProvider::addFileImage(
			&m,
			c->getConfig().getInputFile(),
			c);
	if (f == nullptr)
	{
		return false;
	}

	// TODO:
	// This happens if config is not initialized via fileinfo etc.
	// This is not the right place for this.
	// Refactor the whole thing around this.
	// Reduce the amount of data read from config.
	// Most of these could be read from fileformat.
//==============================================================================
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
	if (auto* pe = dynamic_cast<const fileformat::PeFormat*>(f->getFileFormat()))
	{
		unsigned long long ib = 0;
		if (pe->getImageBaseAddress(ib))
		{
			c->getConfig().setImageBase(ib);
		}
	}
	unsigned long long ep = 0;
	if (f->getFileFormat()->getEpAddress(ep))
	{
		c->getConfig().setEntryPoint(ep);
	}
//==============================================================================
	// TODO:
	// we could probably be using cpdetect results,
	// not reason to translate it to config tools
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
	}
	// TODO: this is needed, but we should remove the whole PIC thing.
	if (c->getConfig().tools.isPic32())
	{
		c->getConfig().architecture.setIsPic32();
	}
//==============================================================================

	auto* abi = AbiProvider::addAbi(&m, c);
	SymbolicTree::setAbi(abi);
	SymbolicTree::setConfig(c);

	// maybe should be in config::Config
	auto typeConfig = std::make_shared<ctypesparser::TypeConfig>();

	auto* d = DemanglerProvider::addDemangler(&m, c, typeConfig);
	if (d == nullptr)
	{
		return false;
	}

	auto* debug = DebugFormatProvider::addDebugFormat(
			&m,
			f->getImage(),
			c->getConfig().getPdbInputFile(),
			c->getConfig().getImageBase(),
			d);

	auto* lti = LtiProvider::addLti(&m, c, typeConfig, f->getImage());

	NamesProvider::addNames(&m, c, debug, f, d, lti);

	AsmInstruction::clear();

	firstRun = false;

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
