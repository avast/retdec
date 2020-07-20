/**
 * @file src/debugformat/dwarf.cpp
 * @brief Common (DWARF and PDB) debug information representation library.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#define LOG_ENABLED false

#include <llvm/DebugInfo/DWARF/DWARFExpression.h>

#include "retdec/demangler/demangler.h"
#include "retdec/utils/debug.h"
#include "retdec/utils/string.h"
#include "retdec/debugformat/debugformat.h"

namespace {

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
	for (auto c : die.children())
	{
		switch (c.getTag())
		{
			case llvm::dwarf::DW_TAG_subprogram:
			{
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
	auto ln = llvm::dwarf::toString(die.find(llvm::dwarf::DW_AT_linkage_name));
	if (!ln.hasValue())
	{
		ln = llvm::dwarf::toString(die.find(llvm::dwarf::DW_AT_MIPS_linkage_name));
	}
	if (ln.hasValue())
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
	if (startLine.isUndefined() && lines)
	{
		if (auto l = lines->lookupAddress(start); l != lines->UnknownRowIndex)
		{
			startLine = lines->Rows[l].Line;
		}
	}
	if (lines)
	{
		if (auto l = lines->lookupAddress(end-1); l != lines->UnknownRowIndex)
		{
			endLine = lines->Rows[l].Line;
		}
	}
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
	else
	{
		dif.returnType.setLlvmIr("void");
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

	return dif;
}

std::string DebugFormat::loadDwarf_type(llvm::DWARFDie die)
{
	// Try to use cache.
	auto it = dieOff2type.find({die.getDwarfUnit(), die.getOffset()});
	if (it != dieOff2type.end())
	{
		return it->second;
	}

	// Insert default type for this die to cache.
	// If procesing this die does not recursively end up here, the cache will
	// get updated with the correct type after it is get and this dummy
	// type is not used.
	// If it does end up here, this will protect us from infinite recursion.
	// Named types (e.g. structures) needs some more hacking in their
	/// processing.
	dieOff2type.insert(
			{{die.getDwarfUnit(), die.getOffset()},
			getDefaultDataType()});

	auto ret = _loadDwarf_type(die);

	dieOff2type[{die.getDwarfUnit(), die.getOffset()}] = ret;

	return ret;
}

std::string DebugFormat::_loadDwarf_type(llvm::DWARFDie die)
{
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
				return getDefaultDataType();
			}
			break;
		}
		case llvm::dwarf::DW_TAG_pointer_type:
		{
			if (auto o = llvm::dwarf::toReference(die.find(llvm::dwarf::DW_AT_type)))
			{
				if (auto odie = die.getDwarfUnit()->getDIEForOffset(o.getValue()))
				{
					return loadDwarf_type(odie) + "*";
				}
			}
			// Default here is pointer to void.
			return "void*";
		}
		case llvm::dwarf::DW_TAG_array_type:
		{
			std::string ret;
			std::string type = getDefaultDataType();
			if (auto o = llvm::dwarf::toReference(die.find(llvm::dwarf::DW_AT_type)))
			{
				if (auto odie = die.getDwarfUnit()->getDIEForOffset(o.getValue()))
				{
					type = loadDwarf_type(odie);
				}
			}
			unsigned dimensions = 0;
			for (auto c : die.children())
			{
				if (c.getTag() == llvm::dwarf::DW_TAG_subrange_type)
				{
					unsigned bound = 0;
					if (auto b = llvm::dwarf::toUnsigned(
							c.find(llvm::dwarf::DW_AT_upper_bound)))
					{
						bound = b.getValue();
					}
					ret += "[ " + std::to_string(bound+1) + " x ";
					++dimensions;
				}
			}
			if (dimensions < 1)
			{
				dimensions = 1;
				ret += "[ 1 x ";
			}
			ret += type;
			for (std::size_t i=0; i<dimensions; i++)
			{
				ret += " ]";
			}
			return ret;
		}
		case llvm::dwarf::DW_TAG_const_type:
		case llvm::dwarf::DW_TAG_typedef:
		case llvm::dwarf::DW_TAG_enumeration_type:
		case llvm::dwarf::DW_TAG_packed_type:
		case llvm::dwarf::DW_TAG_reference_type:
		case llvm::dwarf::DW_TAG_restrict_type:
		case llvm::dwarf::DW_TAG_rvalue_reference_type:
		case llvm::dwarf::DW_TAG_shared_type:
		case llvm::dwarf::DW_TAG_volatile_type:
		{
			if (auto o = llvm::dwarf::toReference(die.find(llvm::dwarf::DW_AT_type)))
			{
				if (auto odie = die.getDwarfUnit()->getDIEForOffset(o.getValue()))
				{
					return loadDwarf_type(odie);
				}
			}
			return getDefaultDataType();
		}
		case llvm::dwarf::DW_TAG_structure_type:
		case llvm::dwarf::DW_TAG_class_type:
		{
			auto it = dieOff2type.find({die.getDwarfUnit(), die.getOffset()});
			// Because we insert default type to cache before processing the
			// type, we need to ignore default types in the map.
			if (it != dieOff2type.end() && it->second != getDefaultDataType())
			{
				return it->second;
			}

			static unsigned anonStuctCntr = 0;
			auto n = llvm::dwarf::toString(die.find(llvm::dwarf::DW_AT_name));
			std::string name = n
					? std::string("%") + n.getValue()
					: "%anon_struct_" + std::to_string(anonStuctCntr++);

			// It is important to insert an entry into cache container before
			// calling loadDwarf_type() recursively.
			// This will prevent infinite cycle if structure contains pointer to
			// itself.
			dieOff2type[{die.getDwarfUnit(), die.getOffset()}] = name;

			std::string body;
			for (auto c : die.children())
			{
				if (c.getTag() == llvm::dwarf::DW_TAG_member)
				{
					std::string elem = getDefaultDataType();
					if (auto o = llvm::dwarf::toReference(c.find(llvm::dwarf::DW_AT_type)))
					{
						if (auto odie = c.getDwarfUnit()->getDIEForOffset(o.getValue()))
						{
							elem = loadDwarf_type(odie);
						}
					}

					body += body.empty() ? "{" : ", ";
					body += elem;
				}
			}
			body += body.empty() ? "{" + getDefaultDataType() + "}" : "}";

			types.insert(name + " = type " + body);
			return name;
		}
		case llvm::dwarf::DW_TAG_subroutine_type:
		{
			std::string ret = "void";
			if (auto o = llvm::dwarf::toReference(die.find(llvm::dwarf::DW_AT_type)))
			{
				if (auto odie = die.getDwarfUnit()->getDIEForOffset(o.getValue()))
				{
					ret = loadDwarf_type(odie);
				}
			}

			std::string body;
			for (auto c : die.children())
			{
				if (c.getTag() == llvm::dwarf::DW_TAG_formal_parameter)
				{
					std::string param = getDefaultDataType();
					if (auto o = llvm::dwarf::toReference(c.find(llvm::dwarf::DW_AT_type)))
					{
						if (auto odie = c.getDwarfUnit()->getDIEForOffset(o.getValue()))
						{
							param = loadDwarf_type(odie);
						}
					}

					body += body.empty() ? "(" : ", ";
					body += param;
				}
			}
			body += body.empty() ? "()" : ")";
			return ret + " " + body;
		}
		default:
		{
			return getDefaultDataType();
		}
	}
}

retdec::common::Object DebugFormat::loadDwarf_formal_parameter(
		llvm::DWARFDie die,
		unsigned argCntr)
{
	std::string name = std::string("a") + std::to_string(argCntr);
	if (auto n = llvm::dwarf::toString(die.find(
			llvm::dwarf::DW_AT_name)))
	{
		const char* nVal = n.getValue();
		if (nVal && std::strlen(nVal) != 0)
		{
			name = nVal;
		}
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
		auto* unit = die.getDwarfUnit();
		auto& ctx = unit->getContext();
		llvm::DataExtractor data(llvm::toStringRef(*o), ctx.isLittleEndian(), 0);
		llvm::DWARFExpression expr(
				data,
				unit->getVersion(),
				unit->getAddressByteSize());

		if (expr.begin() != expr.end())
		{
			auto& e = *expr.begin();

			if (e.getCode() >= llvm::dwarf::DW_OP_breg0
					&& e.getCode() <= llvm::dwarf::DW_OP_breg31
					&& e.getDescription().Op[0] & llvm::DWARFExpression::Operation::SignBit
					&& e.getDescription().Op[1] & llvm::DWARFExpression::Operation::SizeNA)
			{
				unsigned regNum = e.getCode() - llvm::dwarf::DW_OP_breg0;
				int offset = static_cast<int64_t>(e.getRawOperand(0));
				storage = retdec::common::Storage::onStack(offset, regNum);
			}
			else if (e.getCode() == llvm::dwarf::DW_OP_fbreg
					&& e.getDescription().Op[0] & llvm::DWARFExpression::Operation::SignBit
					&& e.getDescription().Op[1] & llvm::DWARFExpression::Operation::SizeNA)
			{
				unsigned regNum = -1;
				int offset = static_cast<int64_t>(e.getRawOperand(0));
				storage = retdec::common::Storage::onStack(offset, regNum);
			}
			else if (e.getCode() == llvm::dwarf::DW_OP_addr
					&& e.getDescription().Op[0] & llvm::DWARFExpression::Operation::SizeAddr
					&& e.getDescription().Op[1] & llvm::DWARFExpression::Operation::SizeNA)
			{
				retdec::common::Address addr = e.getRawOperand(0);
				storage = retdec::common::Storage::inMemory(addr);
			}
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
