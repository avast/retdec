/**
* @file src/bin2llvmir/optimizations/decoder/decoder.cpp
* @brief Decode input binary into LLVM IR.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <iostream>
#include <map>

#include <llvm/IR/InstIterator.h>

#include "retdec/utils/conversion.h"
#include "retdec/utils/string.h"
#include "retdec/bin2llvmir/optimizations/decoder/decoder.h"
#include "retdec/bin2llvmir/utils/defs.h"
#define debug_enabled false
#include "retdec/llvm-support/utils.h"

using namespace retdec::llvm_support;
using namespace retdec::utils;
using namespace retdec::capstone2llvmir;
using namespace llvm;
using namespace retdec::fileformat;

namespace retdec {
namespace bin2llvmir {

char Decoder::ID = 0;

static RegisterPass<Decoder> X(
		"decoder",
		"Input binary to LLVM IR decoding",
		false, // Only looks at CFG
		false // Analysis Pass
);

Decoder::Decoder() :
		ModulePass(ID)
{

}

bool Decoder::runOnModule(Module& m)
{
	_module = &m;
	_config = ConfigProvider::getConfig(_module);
	_image = FileImageProvider::getFileImage(_module);
	_debug = DebugFormatProvider::getDebugFormat(_module);
	return runCatcher();
}

bool Decoder::runOnModuleCustom(
		llvm::Module& m,
		Config* c,
		FileImage* o,
		DebugFormat* d)
{
	_module = &m;
	_config = c;
	_image = o;
	_debug = d;
	return runCatcher();
}

bool Decoder::runCatcher()
{
	try
	{
		return run();
	}
	catch (const Capstone2LlvmIrBaseError& e)
	{
		LOG << "[capstone2llvmir] " << e.what() << std::endl;
		return false;
	}
}

bool Decoder::run()
{
	if (_config == nullptr || _image == nullptr)
	{
		LOG << "[ABORT] Config or object image is not available.\n";
		return false;
	}

	if (initTranslator())
	{
		LOG << "[ABORT] Unable to create Capstone 2 LLVM translator.\n";
		return false;
	}

	initEnvironment();
	initRangesAndTargets();

	doStaticCodeRecognition();
	//TODO - moved after init, because next rewrites SYMBOL_FUNCTION.
	initJumpTargetsWithStaticCode();

	LOG << std::endl;
	LOG << "Allowed ranges:" << std::endl;
	LOG << _allowedRanges << std::endl;
	LOG << std::endl;
	LOG << "Alternative ranges:" << std::endl;
	LOG << _alternativeRanges << std::endl;
	LOG << "Jump targets:" << std::endl;
	LOG << _jumpTargets << std::endl;
	LOG << std::endl;

	doDecoding();
	checkIfSomethingDecoded();

	fixMainName();

	removeStaticallyLinkedFunctions();
	hackDeleteKnownLinkedFunctions();

//dumpModuleToFile(_module);

	fixMipsDelaySlots();

//dumpModuleToFile(_module);

	return true;
}

void Decoder::checkIfSomethingDecoded()
{
	bool hasSomeInsn = false;
	for (Function& f : _module->getFunctionList())
	{
		AsmInstruction ai(&f);
		if (ai.isValid())
		{
			hasSomeInsn = true;
			break;
		}
	}
	if (!hasSomeInsn)
	{
		throw std::runtime_error("No instructions were decoded");
	}
}

void Decoder::initRangesAndTargets()
{
	LOG << "\n initRangesAndTargets():" << std::endl;

	if (_config->getConfig().parameters.isSomethingSelected())
	{
		initAllowedRangesWithConfig();
	}

	if (!_config->getConfig().parameters.isSelectedDecodeOnly())
	{
		initAllowedRangesWithSegments();
	}

	initJumpTargets();
	findDelphiFunctionTable();

	// TODO: This will screw decoding of 2 exotic tests, but removed ranges
	// look ok -- should be removed:
	// extra.features.avg-exotic-pe.TestOnlyEp (F8EEE82B5150B75D4B176CD9804C9F2B.ex)
	// extra.features.avg-exotic-pe.Test_05e86f02582da7e1103b53b6136c1e62
	//
	for (auto& seg : _image->getSegments())
	{
		auto& rc = seg->getNonDecodableAddressRanges();
		for (auto& r : rc)
		{
			if (!r.contains(_config->getConfig().getEntryPoint()))
			{
				_allowedRanges.remove(r.getStart(), r.getEnd());
				_alternativeRanges.remove(r.getStart(), r.getEnd());
			}
		}
	}

	removeZeroSequences(_allowedRanges);
	removeZeroSequences(_alternativeRanges);
}

void Decoder::removeZeroSequences(retdec::utils::AddressRangeContainer& rs)
{
	LOG << "\n" << "removeZeroSequences():" << std::endl;

	static unsigned minSequence = 0x50; // TODO: Maybe should be smaller.
	retdec::utils::AddressRangeContainer toRemove;

	for (auto& range : rs)
	{
		Address start = range.getStart();
		Address end = range.getEnd();
		uint64_t size = range.getSize();

		uint64_t iter = 0;
		Address zeroStart;
		uint64_t byte = 0;
		Address addr;

		while (iter < size)
		{
			addr = start + iter;
			if (_image->getImage()->get1Byte(addr, byte))
			{
				if (byte == 0)
				{
					if (zeroStart.isUndefined())
					{
						zeroStart = addr;
					}
				}
				else
				{
					// +8 -> first few zeroes might be a part of some
					// instruction. only somewhere after them might the real
					// sequence start. if we remove them, we make instruction
					// undecodable.
					//
					if (zeroStart.isDefined()
							&& zeroStart + 8 < addr
							&& addr - zeroStart >= minSequence)
					{
						toRemove.insert(zeroStart+8, addr-1);
					}
					zeroStart = Address::getUndef;
				}

				iter += 1;
			}
			else
			{
				if (zeroStart.isDefined()
						&& zeroStart + 8 < end
						&& end - zeroStart >= minSequence)
				{
					toRemove.insert(zeroStart + 8, end);
				}
				break;
			}
		}

		if (iter >= size
				&& byte == 0
				&& zeroStart.isDefined()
				&& zeroStart + 8 < addr
				&& addr - zeroStart >= minSequence)
		{
			toRemove.insert(zeroStart + 8, addr-1);
		}
	}

	for (auto& range : toRemove)
	{
		LOG << "\t" << range << std::endl;
		rs.remove(range);
	}
}

void Decoder::initJumpTargetsWithStaticCode()
{
	// TODO: Hack, we are hitting main with some other functions on PSP MIPS.
	// Should be solved by using references.
	for (auto& jt : _jumpTargets)
	{
		if (jt.getName() == "main")
		{
			_staticCode.erase(jt.address);
		}
		if (jt.type == JumpTarget::eType::SELECTED_RANGE_START)
		{
			_staticCode.erase(jt.address);
		}
	}

	for (auto& p : _staticCode)
	{
		Address start = p.first;
		Address end = p.second.second.getEnd();
		std::string name = p.second.first;

		cs_mode m = _currentMode;
		if (isArmOrThumb())
		{
			// TODO: We do not really know what mode to use.
			// Even THUMB functions are physically on even addresses in binary.
			// Only their symbols, etc., have odd addresses, but statically
			// linked code finds physical fncs at even addresses.
			// If possible, we should find out what kind of signatures were hit
			// use that. At the moment, we always set ARM, but there are THUMB
			// signature files in the new statically linked code.
			m = CS_MODE_ARM;
		}

		LOG << "\t\tstatically linked: " << name << " @ " << start << std::endl;
		_jumpTargets.push(_config, start, JumpTarget::eType::STATICALLY_LINKED_FUNCTION, m, name);

		Address next = end + 1;
		LOG << "\t\tafter statically linked: " << name << " @ " << end << std::endl;
		_jumpTargets.push(_config, next, JumpTarget::eType::SYMBOL_FUNCTION, m);
	}
}

void Decoder::initAllowedRangesWithSegments()
{
	LOG << "\n initAllowedRangesWithSegments():" << std::endl;

	bool isDotNet = _config->getConfig().languages.hasLanguage(".NET");
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
			LOG << "\t\tsize == 0 -> skipped" << std::endl;
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
					if (isDotNet)
					{
						LOG << "\t\tcode section && .NET -> alternative ranges"
								<< std::endl;
						_alternativeRanges.insert(start, end);
					}
					else
					{
						LOG << "\t\tcode section -> allowed ranges"
								<< std::endl;
						_allowedRanges.insert(start, end);
					}
					break;
				case SecSeg::Type::DATA:
					LOG << "\t\tdata section -> alternative ranges"
							<< std::endl;
					_alternativeRanges.insert(start, end);
					break;
				case SecSeg::Type::CODE_DATA:
					LOG << "\t\tcode/data section -> alternative ranges"
							<< std::endl;
					_alternativeRanges.insert(start, end);
					break;
				case SecSeg::Type::CONST_DATA:
					if (seg.get() == epSeg)
					{
						LOG << "\t\tconst data section == ep seg "
								"-> alternative ranges" << std::endl;
						_alternativeRanges.insert(start, end);
					}
					else
					{
						LOG << "\t\tconst data section -> alternative ranges"
								<< std::endl;
						continue;
					}
					break;
				case SecSeg::Type::UNDEFINED_SEC_SEG:
					LOG << "\t\tundef section -> alternative ranges"
							<< std::endl;
					_alternativeRanges.insert(start, end);
					break;
				case SecSeg::Type::BSS:
					LOG << "\t\tbss section -> skipped" << std::endl;
					continue;
				case SecSeg::Type::DEBUG:
					LOG << "\t\tdebug section -> skipped" << std::endl;
					continue;
				case SecSeg::Type::INFO:
					LOG << "\t\tinfo section -> skipped" << std::endl;
					continue;
				default:
					assert(false && "unhandled section type");
					continue;
			}
		}
		else if (seg.get() == epSeg)
		{
			LOG << "\t\tno underlying section or segment && ep seg "
					"-> alternative ranges" << std::endl;
			_alternativeRanges.insert(start, end);
		}
		else
		{
			LOG << "\t\tno underlying section or segment -> skipped"
					<< std::endl;
			continue;
		}
	}
}

void Decoder::initAllowedRangesWithConfig()
{
	LOG << "\n initAllowedRangesWithConfig():" << std::endl;

	std::set<std::string> foundFs;

	if (!_config->getConfig().parameters.isSelectedDecodeOnly())
	{
		LOG << "\tnot selected decode only -> skipped" << std::endl;
		return;
	}

	for (auto &p : _config->getConfig().parameters.selectedRanges)
	{
		LOG << "\tadd selected range @ " << p << std::endl;
		_allowedRanges.insert(p.getStart(), p.getEnd());
		LOG << "\tadd selected range jump target: " << p.getStart() << std::endl;

		auto m = _currentMode;
		// TODO: What to do here? Do we known from config what kind of code we
		// should decode?

		_jumpTargets.push(_config, p.getStart(), JumpTarget::eType::SELECTED_RANGE_START, m);
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

			if (fIt != selectedFs.end())
			{
				Address start = df.getStart();
				Address end = df.getEnd();

				_allowedRanges.insert(start, end-1);
				LOG << "\tadd selected range jump target: " << start << std::endl;

				auto m = _currentMode;
				// TODO: What to do here? Do we known from config what kind of
				// code we should decode?

				_jumpTargets.push(_config, start, JumpTarget::eType::SELECTED_RANGE_START, m);

				foundFs.insert(*fIt);

				LOG << "\thit in debug functions -- " << *fIt << " @ " << start
						<< " -- " << end << std::endl;
			}
		}

		std::map<retdec::utils::Address, std::shared_ptr<const retdec::fileformat::Symbol>> symtab;
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
						|| selectedFs.count(removeLeadingCharacter(fIt->second->getName(), '_'))
						||  selectedFs.count(removeLeadingCharacter(fIt->second->getNormalizedName(), '_')))
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
				_allowedRanges.insert(start, end-1);
				LOG << "\tadd selected range jump target: " << start << std::endl;

				auto m = _currentMode;
				// TODO: What to do here? Do we known from config what kind of
				// code we should decode?

				_jumpTargets.push(_config, start, JumpTarget::eType::SELECTED_RANGE_START, m);

				foundFs.insert(*fIt);

				LOG << "\thit in symbol table -- " << *fIt << " @ " << start
						<< " -- " << end << std::endl;
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
	if (!_allowedRanges.empty() && plt)
	{
		_allowedRanges.insert(plt->getAddress(), plt->getPhysicalEndAddress()-1);
	}
}

void Decoder::initJumpTargets()
{
	LOG << "\n initJumpTargets():" << std::endl;

	auto m = _currentMode;
	auto bsz = _config->getConfig().architecture.getByteSize();

	// Sections/segments.
	//
	LOG << "\tSections:" << std::endl;
	for (auto& s : _image->getSegments())
	{
		LOG << "\t\tsection: " << s->getName() << " @ "
				<< std::hex << s->getAddress() << std::endl;

		// TODO: We do not know what kind of code is at the start of the
		// section.
		if (isArmOrThumb())
		{
			m = getUnknownMode();
		}

		_jumpTargets.push(_config, s->getAddress(), JumpTarget::eType::SECTION_START, m);
	}

	// Code pointers.
	//
	LOG << "\tCode pointers:" << std::endl;
	std::map<Address, std::pair<Address, const retdec::fileformat::SecSeg*>> codePointers;
	for (auto& seg : _image->getSegments())
	{
		Address start = seg->getAddress();
		Address end = seg->getPhysicalEndAddress();

		for (Address a = start; a < end; a += bsz)
		{
			if (auto* ci = _image->getConstantDefault(a))
			{
				Address val = ci->getZExtValue();
				if (_allowedRanges.contains(val))
				{
					codePointers[a] = std::make_pair(val, seg->getSecSeg());
				}

				// PowerPC style references:
				// 1000b158 (addr): ffff9148 (data) -> reference to 100042a0 (target)
				// target = address + signed(data)
				// 100042a0 = 1000b158 + ffff9148
				// TODO: Does this have something to do with some strange PPC
				// insns? Something like EA computing using this pattern?
				// If so, is it modeled ok? Are we able to compute this kind
				// of targets in control flow computation?
				//
				if (_config->getConfig().architecture.isPpc()
						&& bsz == 4)
				{
					Address target = a + static_cast<int32_t>(val);
					if (_allowedRanges.contains(target))
					{
						codePointers[a] = std::make_pair(target, seg->getSecSeg());
					}
				}
			}
		}
	}

	AddressRange cpr;
	for (auto& p : codePointers)
	{
		Address from = p.first;
		Address to = p.second.first;
		const retdec::fileformat::SecSeg* fromSec = p.second.second;

		bool twoBefore = codePointers.count(from - bsz)
				&& codePointers.count(from - 2*bsz);
		bool twoAfter = codePointers.count(from + bsz)
				&& codePointers.count(from + 2*bsz);
		bool beforeAfter = codePointers.count(from - bsz)
				&& codePointers.count(from + bsz);
		bool continuous = twoBefore || twoAfter || beforeAfter;
		if ((fromSec && fromSec->isDataOnly()) || continuous)
		{
			LOG << "\t\t" << from << " -> " << to << " from DATA" << std::endl;

			// TODO: We do not know what kind of code is at the start of the
			// section.
			if (isArmOrThumb())
			{
				m = to % 2 ? CS_MODE_THUMB : getUnknownMode();
			}

			_jumpTargets.push(
					_config,
					to,
					JumpTarget::eType::CODE_POINTER_FROM_DATA,
					m,
					from);
		}
		else
		{
			// TODO: do not create at all, it is poped and skipped, but
			// marked as popped and because of it other targets with the same
			// address are also skipped.
			//
//			LOG << "\t\t" << from << " -> " << to << " from CODE" << std::endl;
//
//			_jumpTargets.push(
//					to,
//					JumpTarget::eType::CODE_POINTER_FROM_OTHER,
//					from);
		}

		if (cpr.getStart().isUndefined())
		{
			cpr.setStart(from);
			cpr.setEnd(from + bsz - 1);
		}
		else if (cpr.getEnd() + 1 == from) // ane after another
		{
			cpr.setEnd(from + bsz - 1);
		}
		else if (cpr.getEnd() + 1 + bsz >= from
				&& cpr.getSize() >= (2*bsz)
				&& codePointers.count(from + bsz)) // gap <= default arch size
		{
			cpr.setEnd(from + bsz - 1);
		}
		else
		{
			if (cpr.getSize() > (2*bsz))
			{
				LOG << "\t\tremove from allowed ranges = " << cpr << std::endl;
				_allowedRanges.remove(cpr);
			}

			cpr.setStart(from);
			cpr.setEnd(from + bsz - 1);
		}
	}

	// References after ARM functions.
	//
	if (isArmOrThumb())
	{
		LOG << "\tARM after function references:" << std::endl;
		retdec::utils::AddressRangeContainer dataRanges;
		for (auto& seg : _image->getSegments())
		{
			if (auto* sec = seg->getSecSeg())
			{
				if (sec->isSomeData())
				{
					dataRanges.insert(seg->getAddress(), seg->getPhysicalEndAddress());
				}
				else if (sec->isBss())
				{
					dataRanges.insert(seg->getAddress(), seg->getEndAddress());
				}
			}
		}

		std::set<Address> worklist;
		for (auto& r : _allowedRanges)
		{
			for (Address a = r.getStart(); a < r.getEnd(); a += bsz)
			{
				if (auto* ci = _image->getConstantDefault(a))
				{
					Address val = ci->getZExtValue();
					if (dataRanges.contains(val) || _allowedRanges.contains(val) || val == 0)
					{
						worklist.insert(a);
					}
				}
			}
		}

		Address start;
		Address end;
		for (auto a : worklist)
		{
			if (start.isUndefined())
			{
				start = a;
				end = a;
			}
			else if (a == end + bsz)
			{
				end = a;
			}
			// Jump over one missing entry.
			else if (a == (end + 2*bsz))
			{
				end = a;
			}
			else
			{
				if (end - start >= 2*bsz) // 2*bsz -> 3 entries, e.g. 8358 - 8350 -> 8350, 8354, 8358
				{
					_allowedRanges.remove(start, end + bsz - 1);

					_jumpTargets.push(
							_config,
							end + bsz,
							JumpTarget::eType::CODE_POINTER_FROM_DATA,
							getUnknownMode());

					LOG << "\n\t\t" << "removed range: " << start << " -- " << end << std::endl;
					LOG << "\t\t" << "added target @ " << end + bsz << std::endl;
				}

				start = a;
				end = a;
			}
		}
	}

	// Config.
	// TODO: If object file is decompiled, these functions are probably off.
	// See tools.idaplugin.bugs.1706-archives.TestDecompileAll (msvc-factorial-obj.coff).
	// First _factorial() is created at 0x0 from config entry from here.
	// Second _factorial() (renamed by LLVM to _factorial.1()) is later created
	// at decompiled section and renamed based on relocation.
	//
	LOG << "\tConfig:" << std::endl;
	for (auto& p : _config->getConfig().functions)
	{
		retdec::config::Function& f = p.second;
		if (f.getStart().isUndefined())
		{
			continue;
		}

		LOG << "\t\tfunction: " << f.getName() << " @ " << f.getStart()
				<< std::endl;

		if (isArmOrThumb())
		{
			m = f.isThumb() ? CS_MODE_THUMB : CS_MODE_ARM;
		}

		_jumpTargets.push(_config, f.getStart(), JumpTarget::eType::CONFIG_FUNCTION, m, f.getName());
	}
	if (_config->getConfig().isIda())
	{
		return;
	}

	// Entry point.
	//
	LOG << "\tEntry point:" << std::endl;
	auto ep = _config->getConfig().getEntryPoint();
	if (ep.isDefined())
	{
		LOG << "\t\t ep @ " << ep << std::endl;

		if (isArmOrThumb())
		{
			m = ep % 2 ? CS_MODE_THUMB : CS_MODE_ARM;
		}

		_jumpTargets.push(_config, ep, JumpTarget::eType::ENTRY_POINT, m, "entry_point");
	}

	// TODO: Delphi function table.
	// Parsing in function_detection is using decoded ASM, so we can not do it
	// here. Either do the same thing here, but without relying on ASM, or
	// handle this after entry point is decoded, or maybe this will not be
	// necessary -- if there are code pointers in the table, they should be
	// collected by general code pointers finding algorithm (but it would be
	// still better to parse the table for added semantics).

	// Symbols.
	//
	LOG << "\tSymbols:" << std::endl;
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
		retdec::utils::Address addr = a;
		if (addr.isUndefined())
		{
			continue;
		}
		std::string name = s->getName();

		LOG << "\t\tsymbol: " << s->getName() << " @ " << addr << std::endl;

		if (isArmOrThumb())
		{
			m = addr % 2 || s->isThumbSymbol() ? CS_MODE_THUMB : CS_MODE_ARM;
		}

		if (s->getType() == retdec::fileformat::Symbol::Type::PUBLIC)
		{
			_jumpTargets.push(_config, addr, JumpTarget::eType::SYMBOL_FUNCTION_PUBLIC, m, name);
		}
		else
		{
			_jumpTargets.push(_config, addr, JumpTarget::eType::SYMBOL_FUNCTION, m, name);
		}
	}

	// Exports.
	//
	LOG << "\tExports:" << std::endl;
	if (auto *exTbl = _image->getFileFormat()->getExportTable())
	{
		for (const auto &exp : *exTbl)
		{
			retdec::utils::Address addr = exp.getAddress();
			if (addr.isUndefined())
			{
				continue;
			}
			std::string name = normalizeNamePrefix(exp.getName());

			LOG << "\t\texport: " << exp.getName() << " @ " << addr << std::endl;

			if (isArmOrThumb())
			{
				m = addr % 2 ? CS_MODE_THUMB : CS_MODE_ARM;
			}

			_jumpTargets.push(_config, addr, JumpTarget::eType::EXPORT_FUNCTION, m, name);
		}
	}

	// Imports.
	//
	Address lowestImport;
	Address highestImport;
	std::size_t importNum = 0;
	LOG << "\tImports:" << std::endl;
	if (auto* impTbl = _image->getFileFormat()->getImportTable())
	{
		for (const auto &imp : *impTbl)
		{
			retdec::utils::Address addr = imp.getAddress();
			if (addr.isUndefined())
			{
				continue;
			}

			if (lowestImport.isUndefined())
			{
				lowestImport = addr;
			}
			if (highestImport.isUndefined())
			{
				highestImport = addr;
			}

			lowestImport = std::min(lowestImport, addr);
			highestImport = std::max(highestImport, addr);
			++importNum;

			std::string n = imp.getName();
			if (n.empty())
			{
				auto libN = impTbl->getLibrary(imp.getLibraryIndex());
				std::transform(libN.begin(), libN.end(), libN.begin(), ::tolower);
				retdec::utils::removeSuffix(libN, ".dll");

				unsigned long long ord;
				const bool ordValid = imp.getOrdinalNumber(ord);
				if (ordValid)
				{
					n = getFunctionNameFromLibAndOrd(libN, ord);
				}
				if (n.empty())
				{
					auto& confGlobs = _config->getConfig().globals;
					if (auto glob = confGlobs.getObjectByAddress(addr))
					{
						n = glob->getName();
					}

					if (n.empty())
					{
						n = "imported_function_ord_" + std::to_string(ord);
					}
				}
			}
			std::string name = normalizeNamePrefix(n);

			LOG << "\t\timport: " << imp.getName() << " @ " << addr << std::endl;

			if (isArmOrThumb())
			{
				m = addr % 2 ? CS_MODE_THUMB : CS_MODE_ARM;
			}

			_jumpTargets.push(_config, addr, JumpTarget::eType::IMPORT_FUNCTION, m, name);
		}
	}
	if (lowestImport.isDefined() && highestImport.isDefined() && importNum > 0)
	{
		std::size_t byteSize = _config->getConfig().architecture.getByteSize();
		Address afterImports = highestImport + byteSize;
		std::size_t sizeImports = afterImports - lowestImport;
		if (sizeImports / importNum <= (byteSize+1))
		{
			if (isArmOrThumb())
			{
				m = getUnknownMode();
			}

			_jumpTargets.push(_config, afterImports, JumpTarget::eType::SECTION_START, m);
			// TODO: maybe remove import table range from decoding ranges?
		}
	}

	// Debug.
	//
	LOG << "\tDebug:" << std::endl;
	if (_debug)
	{
		for (const auto& p : _debug->functions)
		{
			retdec::utils::Address addr = p.first;
			if (addr.isUndefined())
			{
				continue;
			}
			auto& f = p.second;

			LOG << "\t\tdebug: " << f.getName() << " @ " << addr << std::endl;

			// TODO: I have no idea if debug functions are also odd if THUMB.
			if (isArmOrThumb())
			{
				m = addr % 2 || f.isThumb() ? CS_MODE_THUMB : CS_MODE_ARM;
			}

			_jumpTargets.push(_config, addr, JumpTarget::eType::DEBUG_FUNCTION, m, f.getName());
		}
	}

	// TODO: Config selection.
	// It will probably be the best to add start of selected ranges at the
	// time of their selection into ranges to decode.
	//
	// TODO: Abundant-O0-g.ex, large chunks of code pointers, Delphi strings,
	// and other data. Recognize somehow and remove from decoding.
	//
}

void Decoder::doDecoding()
{
	LOG << "\n doDecoding()" << std::endl;

// TODO: Added for ARM, it may screw up some other arch, so it is hacked to work
// only on ARM. It is designed to give original names to jump targets with higher
// priority, e.g. import fnc gets name "malloc", symbol gets name "_malloc".
// Solve it better when all tests pass.
std::set<std::string> seenNames;
	std::map<Address, JumpTarget> orderedJts;
	for (const JumpTarget& jt : _jumpTargets)
	{
		if (jt.createFunction())
		{
			auto fIt = orderedJts.find(jt.address);
			if (fIt == orderedJts.end())
			{
if (_config->getConfig().architecture.isArmOrThumb())
{
	if (jt.hasName() && seenNames.count(jt.getName()))
	{
		jt.setName("_" + jt.getName(_config));
	}
	seenNames.insert(jt.getName(_config));
}

				orderedJts.emplace(jt.address, jt);
			}
			else if ((!fIt->second.hasName()
					|| fIt->second.type == JumpTarget::eType::ENTRY_POINT)
					&& jt.hasName())
			{
if (_config->getConfig().architecture.isArmOrThumb())
{
	if (jt.hasName() && seenNames.count(jt.getName()))
	{
		jt.setName("_" + jt.getName(_config));
	}
	seenNames.insert(jt.getName(_config));
}

				fIt->second.setName(jt.getName(_config));
			}
		}
	}

	Instruction* anyInsn = nullptr;
	std::map<Address, std::pair<Function*, JumpTarget::eType>> functions;
	std::map<Function*, std::string> fncNames;
	std::set<Address> seen;
	// todo: maybe create one more function @ 0x0, if empty at the end,
	// remove it, else rename it to the lowest address.
	for (auto& p : orderedJts)
	{
		auto& jt = p.second;

		if (jt.createFunction())
		{
			if (seen.count(jt.address))
			{
				continue;
			}

			seen.insert(jt.address);

			std::string realName = jt.getName(_config);

			auto* f = llvm::Function::Create(
					llvm::FunctionType::get(
							llvm::Type::getInt32Ty(_module->getContext()),
							false),
					llvm::GlobalValue::ExternalLinkage,
					realName,
					_module);
			llvm::BasicBlock::Create(_module->getContext(), "entry", f);
			llvm::IRBuilder<> irb(&f->front());
			anyInsn = irb.CreateRet(llvm::ConstantInt::get(f->getReturnType(), 0));

			functions[jt.address] = std::make_pair(f, jt.type);

			if (jt.hasName())
			{
				fncNames[f] = realName;
			}
		}
	}
	if (functions.count(0x0) == 0)
	{
		auto* f = llvm::Function::Create(
				llvm::FunctionType::get(
						llvm::Type::getInt32Ty(_module->getContext()),
						false),
				llvm::GlobalValue::ExternalLinkage,
				"",
				_module);
		llvm::BasicBlock::Create(_module->getContext(), "entry", f);
		llvm::IRBuilder<> irb(&f->front());
		anyInsn = irb.CreateRet(llvm::ConstantInt::get(f->getReturnType(), 0));

		functions[0x0] = std::make_pair(f, JumpTarget::eType::SECTION_START);
	}
	if (anyInsn == nullptr)
	{
		return;
	}

	llvm::IRBuilder<> irb(anyInsn);

	Address lowest;
	Address highest;

	std::map<Address, std::pair<AsmInstruction, AsmInstruction>> instrMap;

	while (!_jumpTargets.empty())
	{
		JumpTarget jt = _jumpTargets.top();
		LOG << "\tprocessing : " << jt << std::endl;

		// TODO: je to potrebne? processed range su odstranene z allowed/alternative.
		if (_jumpTargets.wasAlreadyPoped(jt))
		{
			LOG << "\t\ttarget with the same address was already processed "
					"-> skipped" << std::endl;
			_jumpTargets.pop();
			continue;
		}
		_jumpTargets.pop();

		if (jt.from.isDefined() && _processedRanges.contains(jt.from))
		{
			LOG << "\t\ttarget was created from address that was decoded as "
					"code -> skipped" << std::endl;
			continue;
		}

		// It is not safe to use these pointers when static code is not decoded.
		//
		if (jt.type == JumpTarget::eType::CODE_POINTER_FROM_OTHER)
		{
			LOG << "\t\tcode pointers from other jump targets are skipped at "
					"the moment -> skipped" << std::endl;
			continue;
		}

		Address start = jt.address;
		bool inAlternativeRanges = false;
		auto* range = _allowedRanges.getRange(start);
		if (range == nullptr
				&& (jt.type == JumpTarget::eType::CONTROL_FLOW
						|| jt.type == JumpTarget::eType::DELAY_SLOT
						|| jt.type == JumpTarget::eType::ENTRY_POINT
						|| jt.type == JumpTarget::eType::SELECTED_RANGE_START
						|| jt.type == JumpTarget::eType::CONFIG_FUNCTION
						|| jt.type == JumpTarget::eType::DEBUG_FUNCTION
						|| jt.type == JumpTarget::eType::EXPORT_FUNCTION
						|| jt.type == JumpTarget::eType::SYMBOL_FUNCTION
						|| jt.type == JumpTarget::eType::SYMBOL_FUNCTION_PUBLIC))
		{
			range = _alternativeRanges.getRange(start);
			inAlternativeRanges = true;
			if (range)
			{
				LOG << "\t\tfound alternative range : " << *range << std::endl;
			}
		}
		else if (range)
		{
			LOG << "\t\tfound allowed range : " << *range << std::endl;
		}
		if (range == nullptr)
		{
			LOG << "\t\tfound no range -> skipped " << std::endl;
			continue;
		}

		Address nextFncStart;
		Function* f = nullptr;
		auto it = functions.upper_bound(start);
		if (it == functions.begin())
		{
			assert(false && "create function at 0x0");
		}
		else if (it != functions.end())
		{
			nextFncStart = it->first;
			--it;
			f = it->second.first;
		}
		else
		{
			f = functions.rbegin()->second.first;
		}
		assert(f);

		std::size_t size = decodingChunk;
		if (start + size > range->getEnd())
		{
			size = range->getEnd() - start + 1;
		}
		if (nextFncStart.isDefined() && start + size >= nextFncStart)
		{
			size = nextFncStart - start;
		}
if (jt.type == JumpTarget::eType::DELAY_SLOT)
{
	size = 4;
}

		std::vector<std::uint8_t> code;
		std::vector<std::uint64_t> tmp;
		_image->getImage()->get1ByteArray(start, tmp, size);
		std::copy(tmp.begin(), tmp.end(), std::back_inserter(code)); // TODO: no copy -> slow

		LOG << "\t\tsize to decode : " << size << " vs. " << code.size() << std::endl;

cs_mode modeAround = CS_MODE_BIG_ENDIAN;

		auto fIt = instrMap.upper_bound(start);
		if (fIt == instrMap.end())
		{
			irb.SetInsertPoint(&f->back().back());
			LOG << "\t\tinserting after bb : " << f->back().getName().str() << std::endl;
if (isArmOrThumb())
{
	if (auto backAi = AsmInstruction(&f->back().back()))
	{
		modeAround = backAi.isThumb() ? CS_MODE_THUMB : CS_MODE_ARM;
		LOG << "===========> MODE AROUND #1 THUMB: " << backAi.isThumb() << std::endl;
	}
}
		}
		else
		{
			Instruction* insn = fIt->second.first.getLlvmToAsmInstruction();
			if (insn->getFunction() == f)
			{
				irb.SetInsertPoint(insn);
				LOG << "\t\tinserting before instr @ "
						<< fIt->second.first.getAddress()
						<< std::endl;
if (isArmOrThumb())
{
	if (auto backAi = AsmInstruction(insn))
	{
		modeAround = backAi.isThumb() ? CS_MODE_THUMB : CS_MODE_ARM;
		LOG << "===========> MODE AROUND #2 THUMB: " << backAi.isThumb() << std::endl;
	}
}
			}
			else
			{
				irb.SetInsertPoint(&f->back().back());
				LOG << "\t\tinserting after bb : " << f->back().getName().str() << std::endl;
if (isArmOrThumb())
{
	if (auto backAi = AsmInstruction(&f->back().back()))
	{
		modeAround = backAi.isThumb() ? CS_MODE_THUMB : CS_MODE_ARM;
		LOG << "===========> MODE AROUND #3 THUMB: " << backAi.isThumb() << std::endl;
	}
}
			}
		}
		LOG << "\t\tinserting in fnc   : " << f->getName().str() << std::endl;

if (isArmOrThumb())
{
	if (jt.isUnknownMode())
	{
		cs_mode mm = modeAround != getUnknownMode() ? modeAround : CS_MODE_ARM;

LOG << "===========> SWITCH MODE #1 " << _currentMode << " -> " << mm << std::endl;

		// TODO: What here?
		_c2l->modifyBasicMode(mm);
		_currentMode = mm;
	}
	else if (jt.mode != _currentMode)
	{
LOG << "===========> SWITCH MODE #2 " << _currentMode << " -> " << jt.mode << std::endl;

		_c2l->modifyBasicMode(jt.mode);
		_currentMode = jt.mode;
	}
}

		auto tRes = _c2l->translate(code, start, irb, true);
		if (tRes.failed())
		{
			LOG << "\t\ttranslation failed" << std::endl;
			continue;
		}

		// start + size = start of next, we want end of this, therefore -1.
		AddressRange tRange(start, start + tRes.size - 1);
		AsmInstruction first(tRes.first);
		AsmInstruction last(tRes.last);
		CallInst* termCall = tRes.branchCall;

		LOG << "\t\ttranslated : " << tRange << std::endl;
		LOG << "\t\tfirst      : " << first.getAddress() << std::endl;
		LOG << "\t\tlast       : " << last.getAddress() << std::endl;
		LOG << "\t\tbranch call: " << llvmObjToString(termCall) << std::endl;

		_processedRanges.insert(tRange);
		if (inAlternativeRanges)
		{
			_alternativeRanges.remove(tRange);
			LOG << "\t\tremoved from alternative: " << tRange << std::endl;
		}
		else
		{
			_allowedRanges.remove(tRange);
			LOG << "\t\tremoved from allowed    : " << tRange << std::endl;
		}

		instrMap[tRange.getStart()] = {first, last};

		lowest = lowest.isUndefined() ? tRange.getStart() : std::min(lowest, tRange.getStart());
		highest = highest.isUndefined() ? tRange.getEnd() : std::max(highest, tRange.getEnd());

		// TODO: analyze decoded instructions for clues about other jump targets.
		// Right now we analyze only push instruction, but there might be more.
		//
		if (_config->getConfig().architecture.isX86())
		for (auto ai = first; ; ai = ai.getNext())
		{
			cs_insn* capstoneI = ai.getCapstoneInsn();
			cs_x86* xi = &capstoneI->detail->x86;
			Address imm;
			if (capstoneI->id == X86_INS_PUSH
					&& xi->op_count == 1
					&& xi->operands[0].type == X86_OP_IMM)
			{
				imm = xi->operands[0].imm;
			}
			else if (capstoneI->id == X86_INS_MOV
					&& xi->op_count == 2
					&& xi->operands[1].type == X86_OP_IMM)
			{
				imm = xi->operands[1].imm;
			}

			if (looksLikeValidJumpTarget(imm))
			{
				_jumpTargets.push(
						_config,
						imm,
						JumpTarget::eType::CODE_POINTER_FROM_DATA,
						_currentMode);

				LOG << "\t\tpush code pointer @ " << ai.getAddress()
						<< " -> " << std::hex << imm
						<< std::endl;
			}

			if (ai == last)
			{
				break;
			}
		}

		if (_config->isMipsOrPic32())
		for (auto next = first; next.isValid(); next = next.getNext())
		{
			cs_insn* nextC = next.getCapstoneInsn();
			cs_mips* nextM = &nextC->detail->mips;

			if (!(nextC->id == MIPS_INS_ADDIU
					&& nextM->op_count == 3
					&& nextM->operands[0].type == MIPS_OP_REG
					&& nextM->operands[1].type == MIPS_OP_REG
					&& nextM->operands[0].reg == nextM->operands[1].reg
					&& nextM->operands[2].type == MIPS_OP_IMM))
			{
				continue;
			}

			GlobalVariable* loadedReg = _c2l->getRegister(nextM->operands[1].reg);
			if (loadedReg == nullptr)
			{
				continue;
			}

			unsigned cntr = 4;
			auto ai = next.getPrev();
			while (ai.isValid())
			{
				if (ai.storesValue(loadedReg))
				{
					break;
				}
				ai = ai.getPrev();
				--cntr;
				if (cntr == 0)
				{
					ai = AsmInstruction();
					break;
				}
			}
			if (ai.isInvalid())
			{
				continue;
			}

			cs_insn* aiC = ai.getCapstoneInsn();
			cs_mips* aiM = &aiC->detail->mips;

			// lui $a0, 0x40
			// ...
			// addiu $a0, $a0, 0x7c4
			//
			if (aiC->id == MIPS_INS_LUI
					&& aiM->op_count == 2
					&& aiM->operands[0].type == MIPS_OP_REG
					&& aiM->operands[1].type == MIPS_OP_IMM
					&& nextM->operands[1].reg == aiM->operands[0].reg)
			{
				int64_t hi = aiM->operands[1].imm << 16;
				int64_t lo = nextM->operands[2].imm;
				Address target = hi | lo;

				// TODO: there should be more checks that target is ok,
				// probably looksLikeValidJumpTarget() for mips.
				if (((_allowedRanges.contains(target) && target % 4 == 0)
						|| (_alternativeRanges.contains(target) && target % 4 == 0))
						&& looksLikeValidJumpTarget(target))
				{
					_jumpTargets.push(
							_config,
							target,
							JumpTarget::eType::CONTROL_FLOW,
							_currentMode);

					LOG << "\t\tpush code pointer @ " << ai.getAddress()
							<< " -> " << target << std::endl;
				}
			}

			if (next == last)
			{
				break;
			}
		}

		if (isArmOrThumb())
		{
			auto prevLast = last.getPrev();
			if (prevLast)
			{
				for (auto& i : prevLast)
				{
					if (StoreInst* s = dyn_cast<StoreInst>(&i))
					{
						// Next insn address is stored to LR before jump
						// -> add next to jump targets.
						// TODO: Maybe we do not need branch to do this ->
						// all values stored to LR could be jump targets?
						//
						if (_config->isRegister(s->getPointerOperand())
								&& s->getPointerOperand()->getName() == "lr"
								&& isa<ConstantInt>(s->getValueOperand())
								&& cast<ConstantInt>(s->getValueOperand())->getZExtValue() == last.getAddress() + last.getByteSize() )
						{
							auto next = tRange.getEnd() + 1;
							_jumpTargets.push(_config, next, JumpTarget::eType::CONTROL_FLOW, _currentMode);
						}
					}
				}
			}

			for (auto ai = first; ; ai = ai.getNext())
			{
				cs_insn* aiC = ai.getCapstoneInsn();
				cs_arm* aiM = &aiC->detail->arm;
				Address imm;
				if (aiC->id == ARM_INS_LDR
						&& aiM->op_count == 2
						&& aiM->operands[0].type == ARM_OP_REG
						&& aiM->operands[0].reg >= ARM_REG_R0
						&& aiM->operands[0].reg <= ARM_REG_R12
						&& aiM->operands[1].type == ARM_OP_MEM
						&& aiM->operands[1].shift.type == ARM_SFT_INVALID
						&& aiM->operands[1].mem.base == ARM_REG_PC
						&& aiM->operands[1].mem.index == ARM_REG_INVALID
						&& aiM->operands[1].mem.lshift == 0
						&& aiM->operands[1].mem.scale == 1)
				{
					unsigned pcOff = ai.isThumb() ? 4 : 8;
					Address addr = ai.getAddress() + pcOff + aiM->operands[1].mem.disp;
					if (auto* ci = _image->getConstantDefault(addr))
					{
						imm = ci->getZExtValue();
					}
				}

				if (looksLikeValidJumpTarget(imm))
				{
					_jumpTargets.push(
							_config,
							imm,
							JumpTarget::eType::CODE_POINTER_FROM_DATA,
							_currentMode);

					LOG << "\t\tpush code pointer @ " << ai.getAddress()
							<< " -> " << std::hex << imm
							<< std::endl;
				}

				if (ai == last)
				{
					break;
				}
			}
		}

		cs_insn* lastCs = last.getCapstoneInsn();

		if (jt.type == JumpTarget::eType::DELAY_SLOT)
		{
			auto next = tRange.getEnd() + 1;
			if (looksLikeValidJumpTarget(next))
			{
				_jumpTargets.push(
						_config,
						next,
						JumpTarget::eType::CONTROL_FLOW,
						_currentMode);

				LOG << "\t\tpush code pointer after delay slot @ " << last.getAddress()
						<< " -> " << std::hex << next
						<< std::endl;
			}
		}
		// Function call -> insert target (if computed) and next (call should
		// return).
		// TODO: do not insert next if called function is terminating.
		//       e.g. _exit() call @ 08048737 in x86-elf-f6fecb4c80d6c46e3dce02b0d68fc69f
		//       e.g. call sub_4019FC @ 004020AF in 87aa7cdd066541293ffd6761e07b3dad
		//
		else if (_c2l->isCallFunctionCall(tRes.branchCall))
		{
			auto target = getJumpTarget(tRes.branchCall->getArgOperand(0));
			auto next = tRange.getEnd() + 1;
			_jumpTargets.push(_config, target, JumpTarget::eType::CONTROL_FLOW, determineMode(last, target));
			_jumpTargets.push(_config, next, JumpTarget::eType::CONTROL_FLOW, _currentMode);

			LOG << "\t\tcall function call -> " << target << " (target)"
					<< " -> " << next << " (next)" << std::endl;
		}
		// Return call -> insert target (if computed, probably will not be, but
		// it does not matter, return targets are not that important).
		// Next is not inserted, flow does not continue after return.
		//
		else if (_c2l->isReturnFunctionCall(tRes.branchCall))
		{
			auto target = getJumpTarget(tRes.branchCall->getArgOperand(0));

			auto m = _currentMode;
			if (isArmOrThumb())
			{
				m = getUnknownMode();
			}

			_jumpTargets.push(_config, target, JumpTarget::eType::CONTROL_FLOW, m);

			LOG << "\t\treturn function call -> " << target << std::endl;

			auto next = tRange.getEnd() + 1;
if (_c2l->hasDelaySlot(lastCs->id))
{
	_jumpTargets.push(_config, next, JumpTarget::eType::DELAY_SLOT, _currentMode);
}
else if (tRes.inCondition)
{
	_jumpTargets.push(_config, next, JumpTarget::eType::CONTROL_FLOW, _currentMode);
}
			else if (looksLikeValidJumpTarget(next))
			{
				auto m = _currentMode;
				if (isArmOrThumb())
				{
					m = getUnknownMode();
				}

				_jumpTargets.push(
						_config,
						next,
						JumpTarget::eType::CODE_POINTER_FROM_DATA, m);

				LOG << "\t\tpush code pointer after return @ " << last.getAddress()
						<< " -> " << std::hex << next
						<< std::endl;
			}
		}
		// Unconditional branch call -> insert target (if computed).
		// Next is not inserted, flow does not continue after unconditional
		// branch.
		//
		else if (_c2l->isBranchFunctionCall(tRes.branchCall))
		{
			auto target = getJumpTarget(tRes.branchCall->getArgOperand(0));
			_jumpTargets.push(_config, target, JumpTarget::eType::CONTROL_FLOW, determineMode(last, target));

auto next = tRange.getEnd() + 1;
if (_c2l->hasDelaySlot(lastCs->id))
{
	_jumpTargets.push(_config, next, JumpTarget::eType::DELAY_SLOT, _currentMode);
}
else if (tRes.inCondition)
{
	_jumpTargets.push(_config, next, JumpTarget::eType::CONTROL_FLOW, _currentMode);
}
else if ((_config->getConfig().architecture.isPpc() || isArmOrThumb())
		&& looksLikeValidJumpTarget(next))
{
	auto m = _currentMode;
	if (isArmOrThumb())
	{
		m = getUnknownMode();
	}

	_jumpTargets.push(
			_config,
			next,
			JumpTarget::eType::CODE_POINTER_FROM_DATA, m);

	LOG << "\t\tpush code pointer after return @ " << last.getAddress()
			<< " -> " << std::hex << next
			<< std::endl;
}

			LOG << "\t\tbranch function call -> " << target << std::endl;
		}
		// Conditional branch -> insert target (if computed) and next (flow
		// may or may not jump/continue after).
		//
		else if (_c2l->isCondBranchFunctionCall(tRes.branchCall))
		{
			auto target = getJumpTarget(tRes.branchCall->getArgOperand(1));
			auto next = tRange.getEnd() + 1;
			_jumpTargets.push(_config, target, JumpTarget::eType::CONTROL_FLOW, determineMode(last, target));
			_jumpTargets.push(_config, next, JumpTarget::eType::CONTROL_FLOW, _currentMode);

			LOG << "\t\tcond function call -> " << target << " (target)"
					<< " || " << next << " (next)" << std::endl;
		}
		// There is no control flow changing pseudofunction -> continue at the
		// next instruction.
		//
		else if (tRes.branchCall == nullptr)
		{
			auto next = tRange.getEnd() + 1;
			_jumpTargets.push(_config, next, JumpTarget::eType::CONTROL_FLOW, _currentMode);
			LOG << "\t\tno control flow change -> " << next << " (next)"
					<< std::endl;
		}
	}

	LOG << "\nProcessed ranges:" << std::endl;
	LOG << _processedRanges << std::endl;
	LOG << "\nAllowed ranges:" << std::endl;
	LOG << _allowedRanges << std::endl;
	LOG << std::endl;
	LOG << "\nAlternative ranges:" << std::endl;
	LOG << _alternativeRanges << std::endl;

	for (auto& p : functions)
	{
		Address a = p.first;
		Function* f = p.second.first;
		JumpTarget::eType t = p.second.second;

		if (t == JumpTarget::eType::SECTION_START
				&& f->user_empty()
				&& &f->front().front() == &f->back().back())
		{
			f->eraseFromParent();
			continue;
		}

		AsmInstruction firstAi(&f->front().front());
		AsmInstruction lastAi(&f->back().back());

//		Address start = firstAi.isValid() ? firstAi.getAddress() : a;
		Address start = a;
		if (t == JumpTarget::eType::CONTROL_FLOW
				|| t == JumpTarget::eType::DELAY_SLOT
				|| t == JumpTarget::eType::CODE_POINTER_FROM_DATA
				|| t == JumpTarget::eType::CODE_POINTER_FROM_OTHER
				|| t == JumpTarget::eType::SECTION_START)
		{
			start = firstAi.isValid() ? firstAi.getAddress() : a;
		}

		Address end = lastAi.isValid()
				? Address(lastAi.getAddress() + lastAi.getByteSize() - 1) // TODO: getEndAddress() should do start + size - 1
				: start;

		if (f->getName().empty() || f->getName() == "entry_point") // TODO: entry point nicer
		{
			// This gets names even from non-function symbols that were not used
			// as jump targets.
			//
			if (auto* sym = _image->getPreferredSymbol(start))
			{
				f->setName(sym->getName());
				fncNames[f] = sym->getName();
			}
		}

		if (f->getName().empty())
		{
			if (_config->getConfig().isIda())
			{
				f->setName(retdec::utils::appendHexRet("sub", start));
			}
			else
			{
				f->setName(retdec::utils::appendHexRet("function", start));
			}
		}

		if (&f->front().front() == &f->back().back())
		{
			f->deleteBody();
		}

		// Probably from IDA. Maybe check if the end address (and other info?)
		// is the same and update?
		//
		if (auto* cf = _config->getConfigFunction(start))
		{
			cf = _config->renameFunction(cf, f->getName());
			cf->setEnd(end);

			// If we have IDA functions, but nothing was selected, then we are
			// doing full decompilation via IDA -> tag functions as static and
			// remove their bodies.
			if (!_config->getConfig().parameters.isSomethingSelected())
			{
				auto slIt = _staticCode.find(a);
				if (slIt != _staticCode.end())
				{
					cf->setIsStaticallyLinked();
				}
			}

			continue;
		}

		auto* cf = _config->insertFunction(f, start, end);
		switch (t)
		{
			case JumpTarget::eType::DEBUG_FUNCTION:
			{
				cf->setIsFromDebug(true);
				break;
			}
			case JumpTarget::eType::IMPORT_FUNCTION:
			{
				cf->setIsDynamicallyLinked();

				// TODO: prev val 8, why is it here? is the limit important?
				unsigned magic = isArmOrThumb() ? 16 : 8;
				if (cf->getSize() <= magic)
				{
					// TODO: This is no good, at this moment, not all functions
					// are detected -- they might split later -- so deleting
					// thi body may delete some other function. It should solve
					// by itselft when whole control flow is here.
					f->deleteBody();
				}
				break;
			}
			default:
			{
				break;
			}
		}

		auto slIt = _staticCode.find(a);
		if (slIt != _staticCode.end())
		{
			cf->setIsStaticallyLinked();
		}

		auto dfIt = _debug->functions.find(a);
		if (dfIt != _debug->functions.end())
		{
			auto& df = dfIt->second;
			cf->setIsFromDebug(true);
			cf->setStartLine(df.getStartLine());
			cf->setEndLine(df.getEndLine());
			cf->setSourceFileName(df.getSourceFileName());
		}

		auto nfIt = fncNames.find(f);
		if (nfIt != fncNames.end() && f->getName() != nfIt->second)
		{
			cf->setRealName(nfIt->second);
		}
	}
}

// Operand is pointer to allowed ranges, but it does not have
// to point to code. Right now, we check that there is
// "push ebp" at the target location.
// TODO: "push ebp" may not be unuque enough, maybe use
// "push ebp ; mov ebp, esp"
// TODO: functions may start with other instructions than
// "push ebp", maybe try to decode the target, or add more
// common patterns.
// TODO: not only fnc addresses might get pushed, there might be
// any other code at the pushed address. e.g.:
// 5f = pop ebp
// e9 ... || eb ... = jmp ...
// we definitely need some better approach than enumerating
// valid start bytes of some random instruction.
// The problem is, that nearly anything can be decoded to valid
// instruction on x86.
//
/**
 * TODO: the best thing here would probably be to get capstone engine from
 * translator and use it to decode some part from the address.
 * Then do some inteligent decision making if the decoded part is ok, or we
 * just decoded some data.
 * e.g.:
 *   - exclude strings/wide strings
 *   - address (or decoded range) should not be loaded or written (it can be
 *   pushed -- pointer to it)
 *   - it should end with some control flow transfer (ret, jmp, br, ...), not
 *     because some data could not be decoded.
 *     Maybe even hlt, exit(), etc, see 0x08056410 and 0x08056418 in 00A2 from
 *     bugs.761.Test
 *   - it should contain reasonable instructions (e.g. push/pop/mov,...), but
 *     it is hard to determine what is reasonable
 *   - maybe do full translation, analyze LLVM and remove it if not good instead
 *     of doing it on an assembly level?
 *   - many genuine code (function) pointer pushes are before calls - parameters
 *
 * TODO: take alignment (NOPS) into acount, not only true NOPS, but also pseudo
 * NOPs like 'mov eax, eax'.
 * e.g. fnc start 00401E5A vs 00401E5C in 87aa7cdd066541293ffd6761e07b3dad
 * from bugs.1046.Test.
 */
bool Decoder::looksLikeValidJumpTarget(retdec::utils::Address addr)
{
	if (addr.isUndefined()
			|| (!_allowedRanges.contains(addr) && !_alternativeRanges.contains(addr)))
	{
		return false;
	}

	if (!_config->isMipsOrPic32() && !_allowedRanges.contains(addr))
	{
		return false;
	}

	auto* chars = dyn_cast_or_null<ConstantDataSequential>(
			_image->getConstantCharArrayNice(addr));
	if (chars && chars->getNumElements() > 3)
	{
		return false;
	}

	std::vector<std::uint64_t> wchars;
	unsigned wcharSize = _image->getFileFormat()->isElf() ? 4 : 2;
	if (_image->getImage()->getNTWSNice(addr, wcharSize, wchars)
			&& wchars.size() > 2)
	{
		return false;
	}

	uint64_t byte = 0;

	if (_config->getConfig().architecture.isX86())
	if (_image->getImage()->get1Byte(addr, byte)
			&& (byte == 0x55 // push ebp
					|| byte == 0x68 // push immX
					|| byte == 0x56 // pop esi
					|| byte == 0x53 // pop ebx
					|| byte == 0x57 // pop edi
					|| byte == 0x5d // pop ebp
					|| byte == 0x8b // mov
					|| byte == 0xb8 // mov
					|| byte == 0x83 // sub
					|| byte == 0xff // jmp
					|| byte == 0xe9 // start of call
					|| byte == 0xeb))  // start of call
//					|| byte == 0x6a)) // 6a 00 == push 0
	{
		return true;
	}

	// TODO: Make it stricter, fist instruction should be something known:
	// e.g. "addiu $sp. X", "lui $gp, X", "lui $a0, 0x43".
	//
	if (_config->isMipsOrPic32())
	{
		static const unsigned insnNum = 4;
		std::vector<std::uint8_t> code;
		std::vector<std::uint64_t> tmp;
		_image->getImage()->get1ByteArray(addr, tmp, insnNum*4);
		std::copy(tmp.begin(), tmp.end(), std::back_inserter(code)); // TODO: no copy -> slow
		auto& engine = _c2l->getCapstoneEngine();
		cs_insn* insn = nullptr;
		const uint8_t* c = code.data();
		size_t count = cs_disasm(engine, c, code.size(), addr, 0, &insn);
		if (count > 0)
		{
			cs_free(insn, count);
		}
		if (count == insnNum) // all data were successfully disassembled into instructions.
		{
			return true;
		}
		else if (_c2l->getBasicMode() == CS_MODE_MIPS32)
		{
			insn = nullptr;
			_c2l->modifyBasicMode(CS_MODE_MIPS64);
			count = cs_disasm(engine, c, code.size(), addr, 0, &insn);
			_c2l->modifyBasicMode(CS_MODE_MIPS32);
			if (count > 0)
			{
				cs_free(insn, count);
			}
			if (count == insnNum) // all data were successfully disassembled into instructions.
			{
				return true;
			}
		}
	}
	// Make it stricter, fist instruction should be something known:
	// e.g. "mflr r0", " stwu r1, X"
	//
	if (_config->getConfig().architecture.isPpc())
	{
		static const unsigned insnNum = 4;
		std::vector<std::uint8_t> code;
		std::vector<std::uint64_t> tmp;
		_image->getImage()->get1ByteArray(addr, tmp, insnNum*4);
		std::copy(tmp.begin(), tmp.end(), std::back_inserter(code)); // TODO: no copy -> slow
		auto& engine = _c2l->getCapstoneEngine();
		cs_insn* insn = nullptr;
		const uint8_t* c = code.data();
		size_t count = cs_disasm(engine, c, code.size(), addr, 0, &insn);
		if (count > 0)
		{
			cs_free(insn, count);
		}
		if (count == insnNum) // all data were successfully disassembled into instructions.
		{
			return true;
		}
	}

	if (_config->getConfig().architecture.isArmOrThumb())
	{
		static const unsigned insnNum = 4;
		std::vector<std::uint8_t> code;
		std::vector<std::uint64_t> tmp;
		_image->getImage()->get1ByteArray(addr, tmp, insnNum*4);
		std::copy(tmp.begin(), tmp.end(), std::back_inserter(code)); // TODO: no copy -> slow
		auto& engine = _c2l->getCapstoneEngine();
		cs_insn* insn = nullptr;
		const uint8_t* c = code.data();
		size_t count = cs_disasm(engine, c, code.size(), addr, 0, &insn);
		if (count > 0)
		{
			cs_free(insn, count);
		}
		if (count == insnNum) // all data were successfully disassembled into instructions.
		{
			return true;
		}
	}

	return false;
}

bool Decoder::initTranslator()
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
		basicMode = CS_MODE_32; // default

		auto bitSz = _config->getConfig().architecture.getBitSize();
		if (bitSz == 16)
		{
			basicMode = CS_MODE_16;
		}
		else if (bitSz == 32)
		{
			basicMode = CS_MODE_32;
		}
		else if (bitSz == 64)
		{
			basicMode = CS_MODE_64;
		}
	}
	else if (_config->getConfig().architecture.isMipsOrPic32())
	{
		arch = CS_ARCH_MIPS;
		basicMode = CS_MODE_MIPS32; // default

		auto bitSz = _config->getConfig().architecture.getBitSize();
		if (bitSz == 32)
		{
			basicMode = CS_MODE_MIPS32;
		}
		else if (bitSz == 64)
		{
			basicMode = CS_MODE_MIPS64;
		}
	}
	else if (_config->getConfig().architecture.isPpc())
	{
		arch = CS_ARCH_PPC;
		basicMode = CS_MODE_32; // default

		auto bitSz = _config->getConfig().architecture.getBitSize();
		if (bitSz == 32)
		{
			basicMode = CS_MODE_32;
		}
		else if (bitSz == 64)
		{
			basicMode = CS_MODE_64;
		}
	}
	else if (_config->getConfig().architecture.isArmOrThumb()
			&& _config->getConfig().architecture.getBitSize() == 32)
	{
		arch = CS_ARCH_ARM;
		basicMode = CS_MODE_ARM;
	}

	_c2l = Capstone2LlvmIrTranslator::createArch(
			arch,
			_module,
			basicMode,
			extraMode);
	_currentMode = basicMode;
	return false;
}

/**
 * After decoding is done, we need to set some things to config, LLVM module,
 * etc. to initialize bin2llvmirl and decompiler environment so that they know
 * what is what.
 */
void Decoder::initEnvironment()
{
	initEnvironmentAsm2LlvmMapping();
	initEnvironmentPseudoFunctions();
	initEnvironmentRegisters();
}

void Decoder::initEnvironmentAsm2LlvmMapping()
{
	auto* a2lGv = _c2l->getAsm2LlvmMapGlobalVariable();
	a2lGv->setName(_asm2llvmGv);

	_config->setLlvmToAsmGlobalVariable(a2lGv);

	auto* nmd = _module->getOrInsertNamedMetadata(_asm2llvmMd);
	auto* mdString = MDString::get(_module->getContext(), a2lGv->getName());
	auto* mdn = MDNode::get(_module->getContext(), {mdString});
	nmd->addOperand(mdn);
}

void Decoder::initEnvironmentPseudoFunctions()
{
	auto* cf = _c2l->getCallFunction();
	cf->setName(_callFunction);
	_config->setLlvmCallPseudoFunction(cf);

	auto* rf = _c2l->getReturnFunction();
	rf->setName(_returnFunction);
	_config->setLlvmReturnPseudoFunction(rf);

	auto* bf = _c2l->getBranchFunction();
	bf->setName(_branchFunction);
	_config->setLlvmBranchPseudoFunction(bf);

	auto* cbf = _c2l->getCondBranchFunction();
	cbf->setName(_condBranchFunction);
	_config->setLlvmCondBranchPseudoFunction(cbf);

	if (auto* c2lX86 = dynamic_cast<Capstone2LlvmIrTranslatorX86*>(_c2l.get()))
	{
		c2lX86->getX87DataLoadFunction()->setName("__frontend_reg_load.fpr");
		c2lX86->getX87TagLoadFunction()->setName("__frontend_reg_load.fpu_tag");

		c2lX86->getX87DataStoreFunction()->setName("__frontend_reg_store.fpr");
		c2lX86->getX87TagStoreFunction()->setName("__frontend_reg_store.fpu_tag");
	}
}

void Decoder::initEnvironmentRegisters()
{
	for (GlobalVariable& gv : _module->getGlobalList())
	{
		if (_c2l->isRegister(&gv))
		{
			// TODO: this is used in param ordering, and maybe other places.
			// x86 was working without it, but it may not cause problems.
			unsigned regNum = 0;
			if (!_config->getConfig().architecture.isX86())
			{
				regNum = _c2l->getCapstoneRegister(&gv);
			}

			auto s = retdec::config::Storage::inRegister(
					gv.getName(),
					regNum,
					"");

			retdec::config::Object cr(gv.getName(), s);
			cr.type.setLlvmIr(llvmObjToString(gv.getValueType()));
			cr.setRealName(gv.getName());
			_config->getConfig().registers.insert(cr);
		}
	}
}

std::ostream& operator<<(std::ostream &out, const Decoder::JumpTarget& jt)
{
	std::string t;
	switch (jt.type)
	{
		case Decoder::JumpTarget::eType::ENTRY_POINT:
			t = "entry point";
			break;
		case Decoder::JumpTarget::eType::DELAY_SLOT:
			t = "delay slot";
			break;
		case Decoder::JumpTarget::eType::CONTROL_FLOW:
			t = "control flow";
			break;
		case Decoder::JumpTarget::eType::SELECTED_RANGE_START:
			t = "selected range start";
			break;
		case Decoder::JumpTarget::eType::CONFIG_FUNCTION:
			t = "config function";
			break;
		case Decoder::JumpTarget::eType::DEBUG_FUNCTION:
			t = "debug function";
			break;
		case Decoder::JumpTarget::eType::SYMBOL_FUNCTION_PUBLIC:
			t = "symbol function public";
			break;
		case Decoder::JumpTarget::eType::SYMBOL_FUNCTION:
			t = "symbol function";
			break;
		case Decoder::JumpTarget::eType::DELPHI_FNC_TABLE_FUNCTION:
			t = "delphi fnc table function";
			break;
		case Decoder::JumpTarget::eType::EXPORT_FUNCTION:
			t = "export function";
			break;
		case Decoder::JumpTarget::eType::IMPORT_FUNCTION:
			t = "import function";
			break;
		case Decoder::JumpTarget::eType::STATICALLY_LINKED_FUNCTION:
			t = "statically linked function";
			break;
		case Decoder::JumpTarget::eType::CODE_POINTER_FROM_DATA:
			t = "code pointer from data";
			break;
		case Decoder::JumpTarget::eType::CODE_POINTER_FROM_OTHER:
			t = "code pointer from code";
			break;
		case Decoder::JumpTarget::eType::SECTION_START:
			t = "section start";
			break;
		default:
			assert(false && "unknown type");
			t = "unknown";
			break;
	}

	out << jt.address << " (" << t << ")";
	if (jt.hasName())
	{
		out << ", name = " << jt.getName();
	}
	return out;
}

std::ostream& operator<<(std::ostream &out, const Decoder::JumpTargets& jts)
{
	for (auto& jt : jts._data)
	{
		out << jt << std::endl;
	}
	return out;
}

retdec::utils::Address Decoder::getJumpTarget(llvm::Value* val)
{
	if (auto* ci = dyn_cast<ConstantInt>(val))
	{
		return ci->getZExtValue();
	}
	return Address::getUndef;
}

bool Decoder::fixMainName() // TODO: modify right away, do not rename
{
	if (_config->getConfig().isIda())
	{
		return false;
	}

	IrModifier _irmodif(_module, _config);
	if (_module->getFunction("main") == nullptr)
	{
		if (auto* m = _module->getFunction("_main"))
		{
			_irmodif.renameFunction(m, "main");
			return true;
		}
		else if (auto* m = _module->getFunction("wmain"))
		{
			_irmodif.renameFunction(m, "main");
			return true;
		}
	}
	return false;
}

void Decoder::removeStaticallyLinkedFunctions()
{
	// TODO: These functions need to be kept until main detection pass.
	// Main detection needs to run after control flow pass, because it needs
	// pseudo call instructions transformed to call instructions.
	// Merge control flow pass with decoding and move main detection right after it
	// so that all statically linked functions may be removed as soon as possible.
	//
	std::set<std::string> protectedLinked = {
			"__CrtSetReportHookW2",
			"_CrtSetCheckCount",
			"InterlockedExchange",
			"___tmainCRTStartup",
			"_WinMainCRTStartup",
			"WinMainCRTStartup",
	};
	for (Function& f : _module->functions())
	{
		if (protectedLinked.count(f.getName()))
		{
			continue;
		}

		auto* cf = _config->getConfigFunction(&f);
		if (cf && cf->isStaticallyLinked())
		{
			f.deleteBody();
		}
	}
}

void Decoder::hackDeleteKnownLinkedFunctions()
{
	for (Function& f : _module->getFunctionList())
	{
		std::string n = f.getName();
		if (n == "printf" || n == "scanf" || n == "strlen" || n == "strcmp")
		{
			f.deleteBody();
			auto* cff = _config->getConfigFunction(&f);
			if (cff && !cff->isDynamicallyLinked())
			{
				cff->setIsStaticallyLinked();
			}
		}
	}
}

std::string Decoder::getFunctionNameFromLibAndOrd(
		const std::string& libName,
		int ord)
{
	auto it = _dllOrds.find(libName);
	if (it == _dllOrds.end())
	{
		if (!loadOrds(libName))
		{
			return std::string();
		}
		else
		{
			it = _dllOrds.find(libName);
		}
	}

	const OrdMap& ords = it->second;
	auto ordIt = ords.find(ord);
	if (ordIt != ords.end())
	{
		return ordIt->second;
	}

	return std::string();
}

bool Decoder::loadOrds(const std::string& libName)
{
	std::string dir = _config->getConfig().parameters.getOrdinalNumbersDirectory();
	std::string filePath = dir + "/" + libName + ".ord";

	std::ifstream inputFile;
	inputFile.open(filePath);
	if (!inputFile)
	{
		return false;
	}

	std::string line;
	OrdMap ordMap;
	while (!getline(inputFile, line).eof())
	{
		std::stringstream ordDecl(line);

		int ord = -1;
		std::string funcName;
		ordDecl >> ord >> funcName;
		if (ord >= 0)
		{
			ordMap[ord] = funcName;
		}
	}
	inputFile.close();
	_dllOrds.emplace(libName, ordMap);

	return true;
}

void Decoder::findDelphiFunctionTable()
{
	Address ep = _config->getConfig().getEntryPoint();
	if (ep.isUndefined())
	{
		return;
	}
	if (!_config->getConfig().tools.isDelphi()
			|| !_config->getConfig().architecture.isX86())
	{
		return;
	}

	const csh& engine = _c2l->getCapstoneEngine();

	std::vector<std::uint8_t> code;
	std::vector<std::uint64_t> tmp;
	_image->getImage()->get1ByteArray(ep, tmp, 0x20);
	std::copy(tmp.begin(), tmp.end(), std::back_inserter(code));  // TODO: no copy -> slow

	size_t size = code.size();
	const uint8_t* bytes = code.data();
	uint64_t address = ep;
	cs_insn* insn = cs_malloc(engine);
	unsigned cntr = 0;

	bool reached = false;
	while (cs_disasm_iter(engine, &bytes, &size, &address, insn))
	{
		if (++cntr == 4)
		{
			reached = true;
			break;
		}
	}
	if (!reached)
	{
		return;
	}

	if (insn == nullptr || insn->detail == nullptr)
	{
		return;
	}

	retdec::utils::Address tableAddr;
	cs_x86& d = insn->detail->x86;
	if (insn->id == X86_INS_MOV
			&& d.op_count == 2
			&& d.operands[0].type == X86_OP_REG
			&& (d.operands[0].reg == X86_REG_EAX
					|| d.operands[0].reg == X86_REG_RAX)
			&& d.operands[1].type == X86_OP_IMM)
	{
		tableAddr = d.operands[1].imm;
	}

	if (tableAddr.isUndefined())
	{
		return;
	}

	cs_free(insn, 1);

	retdec::utils::Address tableAddrEnd = tableAddr;

	LOG << "Delphi function table @ " << tableAddr << std::endl;

	auto* tableSeg = _image->getImage()->getSegmentFromAddress(tableAddr);
	auto currentAddr = tableAddr;
	ConstantInt* currentCi = nullptr;
	std::size_t entrySize = 0;
	while ((currentCi = _image->getConstantDefault(currentAddr)))
	{
		retdec::utils::Address currentVal = currentCi->getZExtValue();

		if (currentVal.isUndefined()
				|| currentVal == 0
				|| _image->getImage()->getSegmentFromAddress(currentAddr) != tableSeg)
		{
			break;
		}
		tableAddrEnd = currentAddr;

		LOG << "\t" << currentAddr << " -> " << currentVal << std::endl;
		_jumpTargets.push(_config, currentVal, JumpTarget::eType::DELPHI_FNC_TABLE_FUNCTION, _currentMode);

		entrySize = currentCi->getBitWidth() / 8;
		currentAddr += entrySize;
	}

	if (tableAddrEnd > tableAddr)
	{
		tableAddrEnd += entrySize - 1;
		AddressRange r(tableAddr, tableAddrEnd);
		_allowedRanges.remove(r);
		_alternativeRanges.remove(r);
	}

	LOG << "====> END @ " << tableAddrEnd << std::endl;
}

void Decoder::fixMipsDelaySlots()
{
	if (!_config->isMipsOrPic32())
	{
		return;
	}

	for (Function& F : _module->getFunctionList())
	for (auto ai = AsmInstruction(&F); ai.isValid(); ai = ai.getNext())
	{
		cs_insn* ci = ai.getCapstoneInsn();
		std::size_t ds = _c2l->getDelaySlot(ci->id);

		if (ds) // && _c2l->hasDelaySlotTypical(ci->id)) // TODO
		{
			auto next = ai.getNext();
			if (next.isInvalid())
			{
				continue;
			}
			if (_c2l->hasDelaySlot(next.getCapstoneInsn()->id))
			{
				ai = next;
				continue;
			}

			// TODO: This is not perfect. There could be more BBs in AIs, but
			// not branches?
			// Thre could be more pseudo branches in the first AI.
			//
			auto* brAi = ai.getInstructionFirst<BranchInst>();
			auto* brNext = next.getInstructionFirst<BranchInst>();
			if (brNext == nullptr)
			{
				bool done = false;
				for (auto rit = ai.rbegin(); rit != ai.rend(); ++rit)
				{
					Instruction& ri = *rit;
					if (_config->isLlvmAnyBranchPseudoFunctionCall(&ri))
					{
						auto* first = &ri;
						auto is = next.getInstructions();
						auto* term = next.getBasicBlock()->getTerminator();
						for (Instruction* i : is)
						{
							if (i != term)
							{
								i->moveBefore(first);
							}
						}

						done = true;
						break;
					}
				}
				if (done)
				{
					continue;
				}

				auto* first = ai.front();
				if (first == nullptr)
				{
					first = next.getLlvmToAsmInstruction();
				}
				auto is = next.getInstructions();
				auto* term = next.getBasicBlock()->getTerminator();
				for (Instruction* i : is)
				{
					if (i != term)
					{
						i->moveBefore(first);
					}
				}
			}
			else if (brAi == nullptr)
			{
				Instruction* first = nullptr;
				if (auto next2 = next.getNext())
				{
					first = next2.getLlvmToAsmInstruction();
				}
				else
				{
					first = next.back();
				}

				bool done = false;
				for (auto rit = ai.rbegin(); rit != ai.rend(); ++rit)
				{
					Instruction& ri = *rit;
					if (_config->isLlvmAnyBranchPseudoFunctionCall(&ri))
					{
						ri.moveBefore(first);

						done = true;
						break;
					}
				}
				if (done)
				{
					continue;
				}

				auto is = ai.getInstructions();
				auto* term = ai.getBasicBlock()->getTerminator();
				for (Instruction* i : is)
				{
					if (i != term)
					{
						i->moveBefore(first);
					}
				}
			}
			else
			{
				// TODO: we can not move instructions with branches -> BBs.
			}
		}
		else if (ds && _c2l->hasDelaySlotLikely(ci->id))
		{
//			std::cout << "likely DS  @ " << ai.getAddress() << "  <====================" << std::endl;
			// TODO: move to
		}
		else if (ds)
		{
			assert(false && "unhandled delay slot type");
		}
	}
}

bool Decoder::isArmOrThumb() const
{
	return _config->getConfig().architecture.isArmOrThumb();
}

cs_mode Decoder::getUnknownMode() const
{
	return CS_MODE_BIG_ENDIAN;
}

cs_mode Decoder::determineMode(AsmInstruction ai, retdec::utils::Address target) const
{
	if (target.isUndefined())
	{
		return _currentMode; // whatever, this can not be used anyway.
	}
	if (!isArmOrThumb())
	{
		return _currentMode;
	}

	auto* cs = ai.getCapstoneInsn();

	// Mode is not switched.
	//
	if (cs->id != ARM_INS_BX && cs->id != ARM_INS_BLX)
	{
		return _currentMode;
	}

	auto m = target % 2 ? CS_MODE_THUMB : CS_MODE_ARM;

	return m;
}

} // namespace bin2llvmir
} // namespace retdec
