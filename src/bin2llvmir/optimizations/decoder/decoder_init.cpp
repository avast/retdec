/**
* @file src/bin2llvmir/optimizations/decoder/decoder.cpp
* @brief Various decoder initializations.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include "retdec/bin2llvmir/optimizations/decoder/decoder.h"
#include "retdec/utils/string.h"

using namespace retdec::utils;
using namespace retdec::capstone2llvmir;
using namespace llvm;
using namespace retdec::fileformat;

namespace retdec {
namespace bin2llvmir {

/**
 * Initialize capstone2llvmir translator according to the architecture of
 * file to decompile.
 * @return @c True if error, @c false otherwise.
 */
void Decoder::initTranslator()
{
	auto& a = _config->getConfig().architecture;

	cs_arch arch = CS_ARCH_ALL;
	cs_mode basicMode = CS_MODE_LITTLE_ENDIAN;
	cs_mode extraMode = a.isEndianBig()
			? CS_MODE_BIG_ENDIAN
			: CS_MODE_LITTLE_ENDIAN;

	if (a.isX86())
	{
		arch = CS_ARCH_X86;
		switch (_config->getConfig().architecture.getBitSize())
		{
			case 16: basicMode = CS_MODE_16; break;
			case 64: basicMode = CS_MODE_64; break;
			default:
			case 32: basicMode = CS_MODE_32; break;
		}
	}
	else if (a.isMipsOrPic32())
	{
		arch = CS_ARCH_MIPS;
		switch (_config->getConfig().architecture.getBitSize())
		{
			case 64: basicMode = CS_MODE_MIPS64; break;
			default:
			case 32: basicMode = CS_MODE_MIPS32; break;
		}
	}
	else if (a.isPpc())
	{
		arch = CS_ARCH_PPC;
		switch (_config->getConfig().architecture.getBitSize())
		{
			case 64: basicMode = CS_MODE_64; break;
			default:
			case 32: basicMode = CS_MODE_32; break;
		}
	}
	else if (a.isArmOrThumb()
			&& a.getBitSize() == 32)
	{
		arch = CS_ARCH_ARM;
		basicMode = CS_MODE_ARM; // We start with ARM mode even for THUMB.
	}
	else
	{
		throw std::runtime_error("Unsupported architecture.");
	}

	_c2l = Capstone2LlvmIrTranslator::createArch(
			arch,
			_module,
			basicMode,
			extraMode);
}

/**
 * Initialize instruction used in dry run disassembly.
 */
void Decoder::initDryRunCsInstruction()
{
	csh ce = _c2l->getCapstoneEngine();
	_dryCsInsn = cs_malloc(ce);
}

/**
 * Synchronize metadata between capstone2llvmir and bin2llvmir.
 */
void Decoder::initEnvironment()
{
	initEnvironmentAsm2LlvmMapping();
	initEnvironmentPseudoFunctions();
	initEnvironmentRegisters();
}

/**
 * Find out from capstone2llvmir which global is used for
 * LLVM IR <-> Capstone ASM mapping.
 * 1. Set its name.
 * 2. Set it to config.
 * 3. Create metadata for it, so it can be quickly recognized without querying
 *    config.
 */
void Decoder::initEnvironmentAsm2LlvmMapping()
{
	auto* a2lGv = _c2l->getAsm2LlvmMapGlobalVariable();
	a2lGv->setName(names::asm2llvmGv);

	AsmInstruction::setLlvmToAsmGlobalVariable(_module, a2lGv);
}

/**
 * Set pseudo functions' names in LLVM IR and set them to config.
 */
void Decoder::initEnvironmentPseudoFunctions()
{
	auto* cf = _c2l->getCallFunction();
	cf->setName(names::pseudoCallFunction);
	_config->setLlvmCallPseudoFunction(cf);

	auto* rf = _c2l->getReturnFunction();
	rf->setName(names::pseudoReturnFunction);
	_config->setLlvmReturnPseudoFunction(rf);

	auto* bf = _c2l->getBranchFunction();
	bf->setName(names::pseudoBranchFunction);
	_config->setLlvmBranchPseudoFunction(bf);

	auto* cbf = _c2l->getCondBranchFunction();
	cbf->setName(names::pseudoCondBranchFunction);
	_config->setLlvmCondBranchPseudoFunction(cbf);

	if (auto* c2lX86 = dynamic_cast<Capstone2LlvmIrTranslatorX86*>(_c2l.get()))
	{
		c2lX86->getX87DataLoadFunction()->setName(
				names::pseudoX87dataLoadFunction);
		c2lX86->getX87TagLoadFunction()->setName(
				names::pseudoX87tagLoadFunction);
		c2lX86->getX87DataStoreFunction()->setName(
				names::pseudoX87dataStoreFunction);
		c2lX86->getX87TagStoreFunction()->setName(
				names::pseudoX87tagStoreFunction);
	}
}

/**
 * Create config objects for HW registers.
 * Initialize ABI with registers.
 */
void Decoder::initEnvironmentRegisters()
{
	for (GlobalVariable& gv : _module->globals())
	{
		if (_c2l->isRegister(&gv))
		{
			unsigned regNum = _c2l->getCapstoneRegister(&gv);
			auto s = config::Storage::inRegister(
					gv.getName(),
					regNum,
					"");

			config::Object cr(gv.getName(), s);
			cr.type.setLlvmIr(llvmObjToString(gv.getValueType()));
			cr.setRealName(gv.getName());
			_config->getConfig().registers.insert(cr);

			_abi->addRegister(regNum, &gv);
		}
	}
}

/**
 * Find address ranges to decode.
 */
void Decoder::initRanges()
{
	JumpTarget::config = _config;
	JumpTargets::config = _config;

	auto& arch = _config->getConfig().architecture;
	unsigned a = 0;
	a = arch.isArmOrThumb() ? 2 : a;
	a = arch.isMipsOrPic32() ? 4 : a;
	a = arch.isPpc() ? 4 : a;
	_ranges.setArchitectureInstructionAlignment(a);

	if (_config->getConfig().parameters.isSelectedDecodeOnly())
	{
		initAllowedRangesWithConfig();
	}
	else
	{
		initAllowedRangesWithSegments();
	}

	_ranges.removeZeroSequences(_image);

	if (_ranges.primaryEmpty())
	{
		_ranges.promoteAlternativeToPrimary();
	}
}

/**
 * Initialize address ranges to decode from image segments/sections.
 */
void Decoder::initAllowedRangesWithSegments()
{
	LOG << "\n" << "initAllowedRangesWithSegments():" << std::endl;

	auto* epSeg = _image->getImage()->getEpSegment();
	for (auto& seg : _image->getSegments())
	{
		auto* sec = seg->getSecSeg();
		Address start = seg->getAddress();
		Address end = seg->getPhysicalEndAddress();

		LOG << "\t" << seg->getName() << " @ " << start << " -- "
				<< end << std::endl;

		if (start == end)
		{
			LOG << "\t\t" << "size == 0 -> skipped" << std::endl;
			continue;
		}

		if (seg.get() != epSeg && sec)
		{
			if (auto* s = dynamic_cast<const PeCoffSection*>(sec))
			{
				if (s->getPeCoffFlags() & PeLib::PELIB_IMAGE_SCN_MEM_DISCARDABLE)
				{
					LOG << "\t\t" << "PeLib::PELIB_IMAGE_SCN_MEM_DISCARDABLE"
							" -> skipped" << std::endl;
					continue;
				}
			}
		}

		if (sec)
		{
			switch (sec->getType())
			{
				case SecSeg::Type::CODE:
					LOG << "\t\t" << "code -> allowed ranges"
							<< std::endl;
					if (sec->getName() == ".plt" // usually marked as code
						|| sec->getName() == ".got" // usually marked as data
						|| sec->getName() == ".got.plt")
					{
						_ranges.addAlternative(start, end);
					}
					else
					{
						_ranges.addPrimary(start, end);
					}
					break;
				case SecSeg::Type::DATA:
					LOG << "\t\t" << "data -> alternative ranges"
							<< std::endl;
					_ranges.addAlternative(start, end);
					break;
				case SecSeg::Type::CODE_DATA:
					LOG << "\t\t" << "code/data -> alternative ranges"
							<< std::endl;
					_ranges.addAlternative(start, end);
					break;
				case SecSeg::Type::CONST_DATA:
					if (seg.get() == epSeg)
					{
						LOG << "\t\t" << "const data == ep seg "
								"-> alternative ranges" << std::endl;
						_ranges.addAlternative(start, end);
					}
					else
					{
						LOG << "\t\t" << "const data -> alternative ranges"
								<< std::endl;
						continue;
					}
					break;
				case SecSeg::Type::UNDEFINED_SEC_SEG:
					LOG << "\t\t" << "undef -> alternative ranges"
							<< std::endl;
					_ranges.addAlternative(start, end);
					break;
				case SecSeg::Type::BSS:
					LOG << "\t\t" << "bss -> skipped" << std::endl;
					continue;
				case SecSeg::Type::DEBUG:
					LOG << "\t\t" << "debug -> skipped" << std::endl;
					continue;
				case SecSeg::Type::INFO:
					LOG << "\t\t" << "info -> skipped" << std::endl;
					continue;
				default:
					assert(false && "unhandled section type");
					continue;
			}
		}
		else if (seg.get() == epSeg)
		{
			LOG << "\t\t" << "no underlying section or segment && ep seg "
					"-> alternative ranges" << std::endl;
			_ranges.addAlternative(start, end);
		}
		else
		{
			LOG << "\t\t" << "no underlying section or segment -> skipped"
					<< std::endl;
			continue;
		}
	}

	for (auto& seg : _image->getSegments())
	{
		auto& rc = seg->getNonDecodableAddressRanges();
		for (auto& r : rc)
		{
			if (!r.contains(_config->getConfig().getEntryPoint()))
			{
				_ranges.remove(r.getStart(), r.getEnd());
			}
		}
	}
}

void Decoder::initAllowedRangesWithConfig()
{
	LOG << "\n" << "initAllowedRangesWithConfig():" << std::endl;

	std::set<std::string> foundFs;

	for (auto &p : _config->getConfig().parameters.selectedRanges)
	{
		_ranges.addPrimary(p);
		LOG << "\t" << "[+] selected range @ " << p << std::endl;

		if (auto* jt = _jumpTargets.push(
				p.getStart(),
				JumpTarget::eType::SELECTED_RANGE_START,
				_c2l->getBasicMode(),
				Address::getUndef))
		{
			createFunction(jt->getAddress());
			LOG << "\t" << "[+] " << p.getStart() << std::endl;
		}
		else
		{
			LOG << "\t" << "[-] " << p.getStart() << " (no JT)" << std::endl;
		}
	}

	auto& selectedFs = _config->getConfig().parameters.selectedFunctions;

	if (!selectedFs.empty())
	{
		for (auto& dfp : _debug->functions)
		{
			auto& df = dfp.second;
			auto fIt = selectedFs.find(df.getName());
			if (fIt == selectedFs.end())
			{
				fIt = selectedFs.find(df.getDemangledName());
			}

			if (fIt == selectedFs.end())
			{
				continue;
			}

			Address start = df.getStart();
			Address end = df.getEnd();

			_ranges.addPrimary(start, end);
			LOG << "\t" << "[+] selected range from debug @ "
					<< AddressRange(start, end) << std::endl;

			utils::Maybe<std::size_t> sz;
			auto tmpSz = dfp.second.getSize();
			if (tmpSz.isDefined() && tmpSz > 0)
			{
				sz = tmpSz.getValue();
			}

			if (auto* jt = _jumpTargets.push(
					start,
					JumpTarget::eType::SELECTED_RANGE_START,
					df.isThumb() ? CS_MODE_THUMB : _c2l->getBasicMode(),
					Address::getUndef,
					sz))
			{
				foundFs.insert(*fIt);
				auto* nf = createFunction(jt->getAddress());
				addFunctionSize(nf, sz);
				LOG << "\t" << "[+] " << start << std::endl;
			}
			else
			{
				LOG << "\t" << "[-] " << start << " (no JT)" << std::endl;
			}
		}

		std::map<
				retdec::utils::Address,
				std::shared_ptr<const retdec::fileformat::Symbol>> symtab;

		for (const auto* t : _image->getFileFormat()->getSymbolTables())
		for (const auto& s : *t)
		{
			unsigned long long a = 0;
			if (!s->getRealAddress(a))
			{
				continue;
			}

			auto fIt = symtab.find(a);
			if (fIt == symtab.end())
			{
				symtab.emplace(a, s);
			}
			else
			{
				if (selectedFs.count(fIt->second->getName())
						|| selectedFs.count(fIt->second->getNormalizedName())
						|| selectedFs.count(
								removeLeadingCharacter(
										fIt->second->getName(), '_'))
						|| selectedFs.count(
								removeLeadingCharacter(
										fIt->second->getNormalizedName(), '_')))
				{
					// name in map is the name we are searching for.
				}
				else
				{
					symtab[a] = s;
				}
			}
		}

		for (auto sIt = symtab.begin(); sIt != symtab.end(); ++sIt)
		{
			auto& s = sIt->second;

			retdec::utils::Address start = sIt->first;
			if (start.isUndefined())
			{
				continue;
			}

			utils::Maybe<std::size_t> knownSz;
			unsigned long long size = 0;
			if (!s->getSize(size))
			{
				++sIt;
				if (sIt == symtab.end())
				{
					--sIt;
					continue;
				}
				size = sIt->first - start;
				--sIt;
			}
			else if (size > 0)
			{
				knownSz = size;
			}

			retdec::utils::Address end = start + size;
			std::string name = s->getNormalizedName();

			// Exact name match.
			auto fIt = selectedFs.find(name);

			// Without leading '_' name match.
			if (fIt == selectedFs.end())
			{
				auto tmp1 = removeLeadingCharacter(name, '_');
				for (fIt = selectedFs.begin(); fIt != selectedFs.end(); ++fIt)
				{
					std::string tmp2 = removeLeadingCharacter(*fIt, '_');

					if (tmp1 == tmp2)
						break;
				}
			}

			if (fIt != selectedFs.end() && foundFs.find(*fIt) == foundFs.end())
			{
				_ranges.addPrimary(start, end);
				LOG << "\t" << "[+] selected range from symbol: "
						<< start << std::endl;

				if (auto* jt = _jumpTargets.push(
						start,
						JumpTarget::eType::SELECTED_RANGE_START,
						s->isThumbSymbol() ? CS_MODE_THUMB :_c2l->getBasicMode(),
						Address::getUndef,
						knownSz))
				{
					foundFs.insert(*fIt);
					auto* nf = createFunction(jt->getAddress());
					addFunctionSize(nf, knownSz);
					LOG << "\t" << "[+] " << start << std::endl;
				}
				else
				{
					LOG << "\t" << "[-] " << start << " (no JT)" << std::endl;
				}
			}
		}
	}

	// Find out which selected functions have not been found.
	//
	auto &sbnf = _config->getConfig().parameters.selectedNotFoundFunctions;
	std::set_difference(
			selectedFs.begin(), selectedFs.end(),
			foundFs.begin(), foundFs.end(),
			std::inserter(sbnf, sbnf.end())
	);

	auto* plt = _image->getImage()->getSegment(".plt");
	if (!_ranges.primaryEmpty() && plt)
	{
		_ranges.addPrimary(plt->getAddress(), plt->getPhysicalEndAddress());
	}
}

/**
 * Find jump targets to decode.
 */
void Decoder::initJumpTargets()
{
	initJumpTargetsConfig();
	if (!(_config->getConfig().isIda()
			&& _config->getConfig().parameters.isSomethingSelected()))
	{
		initStaticCode();
	}
	initJumpTargetsEntryPoint();
	initJumpTargetsImports();
	initJumpTargetsDebug();
	initJumpTargetsSymbols(); // MUST be before exports
	initJumpTargetsExports();
	initVtables();
}

void Decoder::initJumpTargetsConfig()
{
	LOG << "\n" << "initJumpTargetsConfig():" << std::endl;

	for (auto& p : _config->getConfig().functions)
	{
		config::Function& f = p.second;
		if (f.getStart().isUndefined())
		{
			continue;
		}

		auto tmpSz = f.getSize();
		auto sz = tmpSz.isDefined() && tmpSz > 0
				? Maybe<std::size_t>(tmpSz)
				: Maybe<std::size_t>();

		if (auto* jt = _jumpTargets.push(
				f.getStart(),
				JumpTarget::eType::CONFIG,
				f.isThumb() ? CS_MODE_THUMB : _c2l->getBasicMode(),
				Address::getUndef,
				sz))
		{
			auto* nf = createFunction(jt->getAddress());
			addFunctionSize(nf, jt->getSize());

			LOG << "\t" << "[+] " << f.getStart() << " @ "
					<< nf->getName().str() << std::endl;
		}
		else
		{
			LOG << "\t" << "[-] " << f.getStart() << " (no JT)" << std::endl;
		}
	}
}

void Decoder::initJumpTargetsEntryPoint()
{
	LOG << "\n" << "initJumpTargetsEntryPoint():" << std::endl;

	auto ep = _config->getConfig().getEntryPoint();
	if (auto* jt = _jumpTargets.push(
			ep,
			JumpTarget::eType::ENTRY_POINT,
			_c2l->getBasicMode(),
			Address::getUndef))
	{
		_entryPointFunction = createFunction(jt->getAddress());

		// TODO: bugs.bin2llvmir-branch-analysis-segfault.Test
		// _image->getImage()->hasDataOnAddress(a) == false -> created fnc is emtpy
		// But we still can get and decode some data.
		if (_entryPointFunction && _entryPointFunction->empty())
		{
			createBasicBlock(jt->getAddress(), _entryPointFunction);
		}

		LOG << "\t" << "[+] " << ep << " @ "
				<< _entryPointFunction->getName().str() << std::endl;
	}
	else
	{
		LOG << "\t" << "[-] " << ep << " (no JT)" << std::endl;
	}
}

void Decoder::initJumpTargetsImports()
{
	LOG << "\n" << "initJumpTargetsImports():" << std::endl;

	auto* impTbl = _image->getFileFormat()->getImportTable();
	if (impTbl == nullptr)
	{
		LOG << "\t" << "no import table -> skip" << std::endl;
		return;
	}

	// Non-pointer imports are preferred.
	// We should solve this somehow better.
	//
	std::set<std::string> usedNames;
	std::set<const fileformat::Import*> ptrs;

	for (const auto &imp : *impTbl)
	{
		utils::Address a = imp->getAddress();
		if (a.isUndefined())
		{
			continue;
		}

		auto* ciVal = _image->getConstantDefault(a);
		auto* sec = _image->getImage()->getSegmentFromAddress(a);

		bool isPtr = false;
		isPtr |= _image->getFileFormat()->isPointer(a);
		isPtr |= ciVal && ciVal->isZero();
		isPtr |= sec && sec->getName() == ".got";
		isPtr |= sec && sec->getName() == ".got.plt";
		if (isPtr)
		{
			ptrs.insert(imp.get());
			continue;
		}

		bool declaration = _config->getConfig().fileFormat.isPe()
				|| _config->getConfig().fileFormat.isCoff();
		if (declaration)
		{
			auto* f = createFunction(a, true);
			_imports.emplace(a);
			if (_image->isImportTerminating(impTbl, imp.get()))
			{
				_terminatingFncs.insert(f);
			}
			usedNames.insert(imp->getName());

			_ranges.remove(a, a+_config->getConfig().architecture.getByteSize());

			continue;
		}

		if (auto* jt = _jumpTargets.push(
				a,
				JumpTarget::eType::IMPORT,
				_c2l->getBasicMode(),
				Address::getUndef))
		{
			auto* f = createFunction(jt->getAddress());
			_imports.emplace(jt->getAddress());
			if (_image->isImportTerminating(impTbl, imp.get()))
			{
				_terminatingFncs.insert(f);
			}
			usedNames.insert(imp->getName());

			LOG << "\t" << "[+] " << a << " @ " << f->getName().str()
					<< std::endl;
		}
		else
		{
			LOG << "\t" << "[-] " << a << " @ " << imp->getName()
					<< " (no JT)" << std::endl;
		}
	}

	for (const auto* imp : ptrs)
	{
		Address a = imp->getAddress();

		if (usedNames.count(imp->getName()))
		{
			LOG << "\t" << "[-] " << a << " @ " << imp->getName()
					<< " (alreadu used name)" << std::endl;
			continue;
		}

		if (auto* jt = _jumpTargets.push(
				a,
				JumpTarget::eType::IMPORT,
				_c2l->getBasicMode(),
				Address::getUndef))
		{
			auto* f = createFunction(jt->getAddress());
			_imports.emplace(jt->getAddress());
			if (_image->isImportTerminating(impTbl, imp))
			{
				_terminatingFncs.insert(f);
			}

			LOG << "\t" << "[+] " << a << " @ " << f->getName().str()
					<< std::endl;
		}
		else
		{
			LOG << "\t" << "[-] " << a << " @ " << imp->getName()
					<< " (no JT)" << std::endl;
		}
	}
}

void Decoder::initJumpTargetsExports()
{
	// TODO: These might be THUMBs without us knowing - no odd address.
	// e.g.
	// features.macho-archives.TestExtractArchiveDecompilation (archive --ar-index 3)
	// run dry run and determine arm/thumb.
	// TODO: also in that sample, it looks like THUMB symbols are -1 not +1.

	LOG << "\n" << "initJumpTargetsExports():" << std::endl;

	auto* exTbl = _image->getFileFormat()->getExportTable();
	if (exTbl == nullptr)
	{
		LOG << "\t" << "no export table -> skip" << std::endl;
		return;
	}

	for (const auto& exp : *exTbl)
	{
		utils::Address addr = exp.getAddress();
		if (addr.isUndefined())
		{
			continue;
		}
		// On ELF, there is no export table. It was reconstructed from
		// symbols. Exports do not have to be functions, they can be
		// data objects. Skip those exports that were not added to symbols.
		//
		if (_config->getConfig().fileFormat.isElf()
				&& _symbols.count(addr) == 0)
		{
			LOG << "\t" << "[-] " << addr << " (no symbol)" << std::endl;
			continue;
		}

		if (auto* jt = _jumpTargets.push(
				addr,
				JumpTarget::eType::EXPORT,
				_c2l->getBasicMode(),
				Address::getUndef))
		{
			auto* nf = createFunction(jt->getAddress());
			_exports.emplace(jt->getAddress());

			LOG << "\t" << "[+] " << addr << " @ " << nf->getName().str()
					<< std::endl;
		}
		else
		{
			LOG << "\t" << "[-] " << addr << " (no JT)" << std::endl;
		}
	}
}

void Decoder::initJumpTargetsSymbols()
{
	LOG << "\n" << "initJumpTargetsSymbols():" << std::endl;

	for (const auto* t : _image->getFileFormat()->getSymbolTables())
	for (const auto& s : *t)
	{
		if (!s->isFunction())
		{
			continue;
		}
		unsigned long long a = 0;
		if (!s->getRealAddress(a))
		{
			continue;
		}
		utils::Address addr = a;

		utils::Maybe<std::size_t> sz;
		unsigned long long tmpSz = 0;
		if (s->getSize(tmpSz) && tmpSz > 0)
		{
			sz = tmpSz;
		}

		if (auto* jt = _jumpTargets.push(
				addr,
				JumpTarget::eType::SYMBOL,
				s->isThumbSymbol() ? CS_MODE_THUMB :_c2l->getBasicMode(),
				Address::getUndef,
				sz))
		{
			auto* nf = createFunction(jt->getAddress());
			_symbols.insert(jt->getAddress());
			addFunctionSize(nf, sz);

			LOG << "\t" << "[+] " << addr << " @ " << nf->getName().str()
					 << " (" << s->getName() << ")" << std::endl;
		}
		else
		{
			LOG << "\t" << "[-] " << addr << " (no JT)" << std::endl;
		}
	}
}

void Decoder::initJumpTargetsDebug()
{
	LOG << "\n" << "initJumpTargetsDebug():" << std::endl;

	if (_debug == nullptr)
	{
		LOG << "\t" << "no debug info -> skip" << std::endl;
		return;
	}

	for (const auto& p : _debug->functions)
	{
		utils::Address addr = p.first;
		if (addr.isUndefined())
		{
			continue;
		}
		auto& f = p.second;

		utils::Maybe<std::size_t> sz;
		auto tmpSz = p.second.getSize();
		if (tmpSz.isDefined() && tmpSz > 0)
		{
			sz = tmpSz.getValue();
		}

		if (auto* jt = _jumpTargets.push(
				addr,
				JumpTarget::eType::DEBUG,
				f.isThumb() ? CS_MODE_THUMB : _c2l->getBasicMode(),
				Address::getUndef,
				sz))
		{
			auto* nf = createFunction(jt->getAddress());
			_debugFncs.emplace(jt->getAddress(), &f);
			addFunctionSize(nf, sz);

			LOG << "\t" << "[+] " << addr << " @ "
					<< nf->getName().str() << std::endl;
		}
		else
		{
			LOG << "\t" << "[-] " << addr << " (no JT)" << std::endl;
		}
	}
}

void Decoder::initStaticCode()
{
	LOG << "\n" << "initStaticCode():" << std::endl;

	StaticCodeAnalysis SCA(
			_config,
			_image,
			_names,
			_c2l->getCapstoneEngine(),
			_c2l->getBasicMode(),
			debug_enabled);

	for (auto& p : SCA.getConfirmedDetections())
	{
		auto* sf = p.second;

		if (auto* jt = _jumpTargets.push(
				sf->address,
				JumpTarget::eType::STATIC_CODE,
				sf->isThumb() ? CS_MODE_THUMB : _c2l->getBasicMode(),
				Address::getUndef,
				sf->size))
		{
			auto* nf = createFunction(jt->getAddress());
			_staticFncs.insert(jt->getAddress());
			if (sf->isTerminating())
			{
				_terminatingFncs.insert(nf);
			}

			// Unreliable - sometimes there are nops, alignment, or other patterns.
			//addFunctionSize(f, sf->size);

			// Speed-up decoding, but we will not be able to diff CFG json
			// with IDA CFG.
			//_ranges.remove(f->address, f->address + f->size);

			LOG << "\t" << "[+] " << sf->address << " @ "
					<< nf->getName().str() << std::endl;
		}
		else
		{
			LOG << "\t" << "[-] " << sf->address << " (no JT)" << std::endl;
		}
	}
}

void Decoder::initVtables()
{
	LOG << "\n" << "initVtables():" << std::endl;

	std::vector<const rtti_finder::Vtable*> vtable;
	for (auto& p : _image->getRtti().getVtablesGcc())
	{
		vtable.push_back(&p.second);
	}
	for (auto& p : _image->getRtti().getVtablesMsvc())
	{
		vtable.push_back(&p.second);
	}

	for (auto* p : vtable)
	{
		auto& vt = *p;
		for (auto& item : vt.virtualFncAddresses)
		{
			if (auto* jt = _jumpTargets.push(
					item.address,
					JumpTarget::eType::VTABLE,
					item.isThumb ? CS_MODE_THUMB : _c2l->getBasicMode(),
					Address::getUndef))
			{
				auto* nf = createFunction(jt->getAddress());
				_vtableFncs.insert(jt->getAddress());

				LOG << "\t" << "[+] " << item.address << " @ "
						<< nf->getName().str() << std::endl;
			}
			else
			{
				LOG << "\t" << "[-] " << item.address << " (no JT)" << std::endl;
			}
		}
	}
}

void Decoder::initConfigFunctions()
{
	for (auto& p : _fnc2addr)
	{
		Function* f = p.first;

		if (_config->getConfigFunction(p.second)) // functions from IDA
		{
			continue;
		}

		Address start = p.second;
		Address end = getFunctionEndAddress(f);
		end = end > start ? end : Address(start + 1);

		auto* cf = _config->insertFunction(f, start, end);

		if (_imports.count(start))
		{
			cf->setIsDynamicallyLinked();
			f->deleteBody();
		}
		else if (_staticFncs.count(start))
		{
			cf->setIsStaticallyLinked();
			// Can not delete body here because of main detection.
			//f->deleteBody();
		}

		std::string realName = _names->getPreferredNameForAddress(start);
		if (cf->getName() != realName)
		{
			cf->setRealName(realName);
		}

		cf->setIsExported(_exports.count(start));

		auto dbgIt = _debugFncs.find(start);
		if (dbgIt != _debugFncs.end())
		{
			auto* df = dbgIt->second;
			cf->setIsFromDebug(true);
			cf->setStartLine(df->getStartLine());
			cf->setEndLine(df->getEndLine());
			cf->setSourceFileName(df->getSourceFileName());
		}
	}
}

} // namespace bin2llvmir
} // namespace retdec
