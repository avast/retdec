/**
 * @file src/debugformat/dwarf.cpp
 * @brief Common (DWARF and PDB) debug information representation library.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#define LOG_ENABLED false

#include <iostream>

#include <llvm/DebugInfo/DWARF/DWARFExpression.h>

#include "retdec/demangler/demangler.h"
#include "retdec/utils/debug.h"
#include "retdec/utils/string.h"
#include "retdec/debugformat/debugformat.h"

namespace {

retdec::common::Address getLineFromAddress(
		const llvm::DWARFDebugLine::LineTable* table,
		retdec::common::Address addr)
{
	retdec::common::Address ret;

	if (table == nullptr)
	{
		return ret;
	}

	llvm::DWARFDebugLine::Row tmpRow;
	tmpRow.Address = addr;
	auto it = std::upper_bound(
			table->Rows.begin(),
			table->Rows.end(),
			tmpRow,
			llvm::DWARFDebugLine::Row::orderByAddress);
	if (it != table->Rows.begin())
	{
		--it;
		ret = it->Line;
	}

	return ret;
}

std::string getDefaultDataType()
{
	return "i32";
}

} // anonymous namespace

namespace retdec {
namespace debugformat {

void DebugFormat::loadDwarf()
{
	// Open input file as buffer.
	//
	llvm::ErrorOr<std::unique_ptr<llvm::MemoryBuffer>> buffOrErr =
			llvm::MemoryBuffer::getFileOrSTDIN(
				_inFile->getFileFormat()->getPathToFile());
	if (buffOrErr.getError())
	{
		return;
	}
	std::unique_ptr<llvm::MemoryBuffer> bufferPtr = std::move(buffOrErr.get());
	llvm::MemoryBufferRef buffer = *bufferPtr;

	// Open buffer as a binary file.
	//
	llvm::Expected<std::unique_ptr<llvm::object::Binary>> binOrErr
			= llvm::object::createBinary(buffer);
	auto binErr = errorToErrorCode(binOrErr.takeError());
	if (binErr)
	{
		return;
	}

	// Handle different flavours of binary files.
	//
	auto* obj = llvm::dyn_cast<llvm::object::ObjectFile>(binOrErr->get());
	if (obj == nullptr)
	{
		// There might be other flavours than llvm::object::ObjectFile.
		// E.g. llvm::object::MachOUniversalBinary, llvm::object::Archive>
		// These are unhandled at the moment.
		return;
	}
	std::unique_ptr<llvm::DWARFContext> DICtx = llvm::DWARFContext::create(*obj);

	LOG << "\n*** DebugFormat::DebugFormat(): DWARF" << std::endl;

	// Inspect compilation unit DIEs.
	//
	for (auto& unit : DICtx->compile_units())
	{
		if (auto unitDie = unit->getUnitDIE(false))
		{
			loadDwarf_CU(unitDie);
		}
	}
}

void DebugFormat::loadDwarf_CU(llvm::DWARFDie die)
{
std::cout << std::hex << die.getOffset() << " @ DIE" << std::endl;
	for (auto c : die.children())
	{
std::cout << std::hex << "\t" << c.getOffset() << std::endl;

		switch (c.getTag())
		{
			case llvm::dwarf::DW_TAG_subprogram:
			{
std::cout << std::hex << "\t\t" << "subprogram" << std::endl;
				auto f = loadDwarf_subprogram(c);
				if (!f.getName().empty() && f.getStart().isDefined())
				{
					functions.insert({f.getStart(), f});
				}
				break;
			}
			case llvm::dwarf::DW_TAG_variable:
			{
				auto v = loadDwarf_variable(c);
				if (!v.getName().empty())
				{
					globals.insert(v);
				}
			}
			default:
				break;
		}
	}
}

retdec::common::Function DebugFormat::loadDwarf_subprogram(llvm::DWARFDie die)
{
	// Start & end address.
	//
	common::Address start, end;
	if (auto s = llvm::dwarf::toAddress(die.find(llvm::dwarf::DW_AT_low_pc)))
	{
		start = s.getValue();
	}
	else if (auto s = llvm::dwarf::toUnsigned(die.find(llvm::dwarf::DW_AT_low_pc)))
	{
		start = s.getValue();
	}
	if (auto e = llvm::dwarf::toAddress(die.find(llvm::dwarf::DW_AT_high_pc)))
	{
		end = e.getValue();
	}
	else if (auto e = llvm::dwarf::toUnsigned(die.find(llvm::dwarf::DW_AT_high_pc)))
	{
		if (start)
		{
			end = start + e.getValue();
		}
	}
	if (start.isUndefined() || end.isUndefined() || end <= start)
	{
		return retdec::common::Function();
	}

	// Names
	//
	std::string name, linkageName, demangledName;
	if (auto n = llvm::dwarf::toString(die.find(
			llvm::dwarf::DW_AT_name)))
	{
		name = n.getValue();
	}
	if (auto ln = llvm::dwarf::toString(die.find(
				llvm::dwarf::DW_AT_linkage_name)))
	{
		linkageName = ln.getValue();
		auto dn = _demangler->demangleToString(linkageName);
		demangledName = dn.empty() ? linkageName : dn;
	}
	if (name.empty() && linkageName.empty())
	{
		return retdec::common::Function();
	}

	auto* unit = die.getDwarfUnit();
	auto* lines = unit->getContext().getLineTableForUnit(unit);

	retdec::common::Function dif(linkageName.empty() ? name : linkageName);

	dif.setIsFromDebug(true);
	dif.setStartEnd(start, end);
	dif.setDemangledName(demangledName);

	auto* sym = _inFile->getFileFormat()->getSymbol(start + 1);
	dif.setIsThumb(sym && sym->isThumbSymbol());

	// Source file name.
	//
	if (auto i = llvm::dwarf::toUnsigned(die.find(llvm::dwarf::DW_AT_decl_file)))
	{
		if (lines)
		{
			std::string declFile;
			if (lines->getFileNameByIndex(
					i.getValue(),
					unit->getCompilationDir(),
					llvm::DILineInfoSpecifier::FileLineInfoKind::AbsoluteFilePath,
					declFile))
			{
				dif.setSourceFileName(declFile);
			}
		}
	}

	// Start & end line.
	//
	retdec::common::Address startLine, endLine;
	if (auto s = llvm::dwarf::toUnsigned(die.find(llvm::dwarf::DW_AT_decl_line)))
	{
		startLine = s.getValue();
	}
	if (startLine.isUndefined())
	{
		startLine = getLineFromAddress(lines, start);
	}
	endLine = getLineFromAddress(lines, end-1);
	dif.setStartLine(startLine);
	dif.setEndLine(endLine);

	// Return type.
	//
	if (auto o = llvm::dwarf::toReference(die.find(llvm::dwarf::DW_AT_type)))
	{
		if (auto odie = unit->getDIEForOffset(o.getValue()))
		{
			dif.returnType = loadDwarf_type(odie);
		}
	}

	// Children.
	//
	unsigned argCntr = 0;
	for (auto c : die.children())
	{
		switch (c.getTag())
		{
			case llvm::dwarf::DW_TAG_unspecified_parameters:
				dif.setIsVariadic(true);
				break;
			case llvm::dwarf::DW_TAG_formal_parameter:
				dif.parameters.push_back(loadDwarf_formal_parameter(c, argCntr++));
				break;
			case llvm::dwarf::DW_TAG_variable:
			{
				auto var = loadDwarf_variable(c);
				if (!var.getName().empty())
				{
					dif.locals.insert(var);
				}
				break;
			}
			default:
				break;
		}
	}

//==============================================================================
std::cout << std::endl;
std::cout << "\t" << "name       : " << dif.getName() << std::endl;
std::cout << "\t" << "range      : " << dif.getStart() << " - " << dif.getEnd() << std::endl;
std::cout << "\t" << "demangled  : " << dif.getDemangledName() << std::endl;
std::cout << "\t" << "src file   : " << dif.getSourceFileName() << std::endl;
std::cout << "\t" << "variadic?  : " << dif.isVariadic() << std::endl;
std::cout << "\t" << "ret type   : " << dif.returnType.getLlvmIr() << std::endl;
std::cout << "\t" << "lines      : " << dif.getStartLine() << " - " << dif.getEndLine() << std::endl;
std::cout << "\t" << "thumb?     : " << dif.isThumb() << std::endl;
std::cout << "\t" << "param #    : " << dif.parameters.size() << std::endl;
for (auto& p : dif.parameters)
{
	std::cout << std::endl;
	std::cout << "\t\t" << "name    : " << p.getName() << std::endl;
	std::cout << "\t\t" << "type    : " << p.type.getLlvmIr() << std::endl;
}
std::cout << "\t" << "local #    : " << dif.locals.size() << std::endl;
for (auto& l : dif.locals)
{
	std::cout << std::endl;
	std::cout << "\t\t" << "name    : " << l.getName() << std::endl;
	std::cout << "\t\t" << "type    : " << l.type.getLlvmIr() << std::endl;
	std::cout << "\t\t" << "stack   : " << l.getStorage().getStackOffset()
			<< " from "
			<< (l.getStorage().getRegisterNumber().has_value()
				? l.getStorage().getRegisterNumber().value()
				: -1)
			<< std::endl;
}
//==============================================================================

	return dif;
}

std::string DebugFormat::loadDwarf_type(llvm::DWARFDie die)
{
	std::string ret = getDefaultDataType();

	switch (die.getTag())
	{
		case llvm::dwarf::DW_TAG_base_type:
		{
			auto n = llvm::dwarf::toString(die.find(llvm::dwarf::DW_AT_name));
			auto e = llvm::dwarf::toUnsigned(die.find(llvm::dwarf::DW_AT_encoding));
			auto Bs = llvm::dwarf::toUnsigned(die.find(llvm::dwarf::DW_AT_byte_size));
			auto bs = llvm::dwarf::toUnsigned(die.find(llvm::dwarf::DW_AT_bit_size));

			if (n && n.getValue() == "void")
			{
				return "void";
			}
			else if (e && e.getValue() == llvm::dwarf::DW_ATE_boolean)
			{
				return "i1";
			}
			else if (e && (
				e.getValue() == llvm::dwarf::DW_ATE_signed ||
				e.getValue() == llvm::dwarf::DW_ATE_signed_char ||
				e.getValue() == llvm::dwarf::DW_ATE_unsigned ||
				e.getValue() == llvm::dwarf::DW_ATE_unsigned_char ||
				e.getValue() == llvm::dwarf::DW_ATE_signed_fixed ||
				e.getValue() == llvm::dwarf::DW_ATE_unsigned_fixed))
			{
				if (bs) return "i" + std::to_string(bs.getValue());
				else if (Bs) return "i" + std::to_string(Bs.getValue() * 8);
				else return getDefaultDataType();
			}
			else if (e && (
				e.getValue() == llvm::dwarf::DW_ATE_complex_float ||
				e.getValue() == llvm::dwarf::DW_ATE_float ||
				e.getValue() == llvm::dwarf::DW_ATE_imaginary_float ||
				e.getValue() == llvm::dwarf::DW_ATE_decimal_float))
			{
				unsigned sz = bs ? bs.getValue() : (Bs ? Bs.getValue()*8 : 32);
				switch (sz)
				{
					case 16: return "half";
					case 32: return "float";
					case 64: return "double";
					case 128: return "fp128";
					case 80: return "x86_fp80";
					default: return "double";
				}
			}
			else
			{
				return getDefaultDataType();;
			}
			break;
		}
		default:
			break;
	}

	types.insert(ret);
	return ret;
}

retdec::common::Object DebugFormat::loadDwarf_formal_parameter(
		llvm::DWARFDie die,
		unsigned argCntr)
{
	std::string name = std::string("a") + std::to_string(argCntr);
	if (auto n = llvm::dwarf::toString(die.find(
			llvm::dwarf::DW_AT_name)))
	{
		name = n.getValue();
	}

	retdec::common::Object arg(name, retdec::common::Storage::undefined());
	arg.type = getDefaultDataType();
	if (auto o = llvm::dwarf::toReference(die.find(llvm::dwarf::DW_AT_type)))
	{
		if (auto odie = die.getDwarfUnit()->getDIEForOffset(o.getValue()))
		{
			arg.type = loadDwarf_type(odie);
		}
	}
	return arg;
}

retdec::common::Object DebugFormat::loadDwarf_variable(llvm::DWARFDie die)
{
	std::string name;
	if (auto n = llvm::dwarf::toString(die.find(
			llvm::dwarf::DW_AT_name)))
	{
		name = n.getValue();
	}
	if (name.empty())
	{
		return retdec::common::Object();
	}

	retdec::common::Storage storage;
	if (auto o = llvm::dwarf::toBlock(die.find(llvm::dwarf::DW_AT_location)))
	{
		if (o.getValue().size() == 2
				&& o.getValue()[0] >= llvm::dwarf::DW_OP_breg0
				&& o.getValue()[0] <= llvm::dwarf::DW_OP_breg31)
		{
			unsigned regNum = o.getValue()[0] - llvm::dwarf::DW_OP_breg0;
			int offset = static_cast<int8_t>(o.getValue()[1]);
			storage = retdec::common::Storage::onStack(offset, regNum);
		}
		else if (o.getValue().size() == 2
				&& o.getValue()[0] == llvm::dwarf::DW_OP_fbreg)
		{
			unsigned regNum = -1;
			int offset = static_cast<int8_t>(o.getValue()[1]);
			storage = retdec::common::Storage::onStack(offset, regNum);
		}
	}

	if (storage.isUndefined())
	{
		return retdec::common::Object();
	}

	retdec::common::Object var(name, storage);
	if (auto o = llvm::dwarf::toReference(die.find(llvm::dwarf::DW_AT_type)))
	{
		if (auto odie = die.getDwarfUnit()->getDIEForOffset(o.getValue()))
		{
			var.type = loadDwarf_type(odie);
		}
	}

	return var;
}

} // namespace debugformat
} // namespace retdec
