/**
* @file src/llvmir2hll/hll/bir_writer.cpp
* @brief Implementation of BIRWriter.
* @copyright (c) 2018 Avast Software, licensed under the MIT license
*/

#include <fstream>

#include "retdec/llvmir2hll/ir/add_op_expr.h"
#include "retdec/llvmir2hll/ir/address_op_expr.h"
#include "retdec/llvmir2hll/ir/and_op_expr.h"
#include "retdec/llvmir2hll/ir/array_index_op_expr.h"
#include "retdec/llvmir2hll/ir/array_type.h"
#include "retdec/llvmir2hll/ir/assign_op_expr.h"
#include "retdec/llvmir2hll/ir/assign_stmt.h"
#include "retdec/llvmir2hll/ir/bit_and_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_cast_expr.h"
#include "retdec/llvmir2hll/ir/bit_or_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_shl_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_shr_op_expr.h"
#include "retdec/llvmir2hll/ir/bit_xor_op_expr.h"
#include "retdec/llvmir2hll/ir/break_stmt.h"
#include "retdec/llvmir2hll/ir/call_expr.h"
#include "retdec/llvmir2hll/ir/call_stmt.h"
#include "retdec/llvmir2hll/ir/comma_op_expr.h"
#include "retdec/llvmir2hll/ir/const_array.h"
#include "retdec/llvmir2hll/ir/const_bool.h"
#include "retdec/llvmir2hll/ir/const_float.h"
#include "retdec/llvmir2hll/ir/const_int.h"
#include "retdec/llvmir2hll/ir/const_null_pointer.h"
#include "retdec/llvmir2hll/ir/const_string.h"
#include "retdec/llvmir2hll/ir/const_struct.h"
#include "retdec/llvmir2hll/ir/const_symbol.h"
#include "retdec/llvmir2hll/ir/continue_stmt.h"
#include "retdec/llvmir2hll/ir/deref_op_expr.h"
#include "retdec/llvmir2hll/ir/div_op_expr.h"
#include "retdec/llvmir2hll/ir/empty_stmt.h"
#include "retdec/llvmir2hll/ir/eq_op_expr.h"
#include "retdec/llvmir2hll/ir/expression.h"
#include "retdec/llvmir2hll/ir/ext_cast_expr.h"
#include "retdec/llvmir2hll/ir/float_type.h"
#include "retdec/llvmir2hll/ir/for_loop_stmt.h"
#include "retdec/llvmir2hll/ir/fp_to_int_cast_expr.h"
#include "retdec/llvmir2hll/ir/function.h"
#include "retdec/llvmir2hll/ir/function_type.h"
#include "retdec/llvmir2hll/ir/global_var_def.h"
#include "retdec/llvmir2hll/ir/goto_stmt.h"
#include "retdec/llvmir2hll/ir/gt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/gt_op_expr.h"
#include "retdec/llvmir2hll/ir/if_stmt.h"
#include "retdec/llvmir2hll/ir/int_to_fp_cast_expr.h"
#include "retdec/llvmir2hll/ir/int_to_ptr_cast_expr.h"
#include "retdec/llvmir2hll/ir/int_type.h"
#include "retdec/llvmir2hll/ir/lt_eq_op_expr.h"
#include "retdec/llvmir2hll/ir/lt_op_expr.h"
#include "retdec/llvmir2hll/ir/mod_op_expr.h"
#include "retdec/llvmir2hll/ir/module.h"
#include "retdec/llvmir2hll/ir/mul_op_expr.h"
#include "retdec/llvmir2hll/ir/neg_op_expr.h"
#include "retdec/llvmir2hll/ir/neq_op_expr.h"
#include "retdec/llvmir2hll/ir/not_op_expr.h"
#include "retdec/llvmir2hll/ir/or_op_expr.h"
#include "retdec/llvmir2hll/ir/pointer_type.h"
#include "retdec/llvmir2hll/ir/ptr_to_int_cast_expr.h"
#include "retdec/llvmir2hll/ir/return_stmt.h"
#include "retdec/llvmir2hll/ir/statement.h"
#include "retdec/llvmir2hll/ir/string_type.h"
#include "retdec/llvmir2hll/ir/struct_index_op_expr.h"
#include "retdec/llvmir2hll/ir/struct_type.h"
#include "retdec/llvmir2hll/ir/sub_op_expr.h"
#include "retdec/llvmir2hll/ir/switch_stmt.h"
#include "retdec/llvmir2hll/ir/ternary_op_expr.h"
#include "retdec/llvmir2hll/ir/trunc_cast_expr.h"
#include "retdec/llvmir2hll/ir/ufor_loop_stmt.h"
#include "retdec/llvmir2hll/ir/unknown_type.h"
#include "retdec/llvmir2hll/ir/unreachable_stmt.h"
#include "retdec/llvmir2hll/ir/var_def_stmt.h"
#include "retdec/llvmir2hll/ir/variable.h"
#include "retdec/llvmir2hll/ir/void_type.h"
#include "retdec/llvmir2hll/ir/while_loop_stmt.h"
#include "retdec/llvmir2hll/hll/bir_writer.h"
#include "retdec/utils/filesystem_path.h"

namespace retdec {
namespace llvmir2hll {

void BIRWriter::emit(Module* m, const std::string& fileName) {
	module = m;

	out.str(std::string());

	emitGlobals();
	emitFunctions();

	utils::FilesystemPath dirName(".");
	static unsigned cntr = 0;
	std::string n = fileName.empty()
			? "dump_" + std::to_string(cntr++) + ".bir"
			: fileName;
	dirName.append(n);
	std::ofstream myfile(dirName.getPath());
	myfile << out.str() << std::endl;
}

void BIRWriter::emitIndent(unsigned indent) {
	out << std::string(indent, '\t');
}

void BIRWriter::emitCurrentIndent() {
	emitIndent(currIndent);
}

void BIRWriter::emitGlobals() {
	out << "Global variables:" << std::endl;
	for (auto it = module->global_var_begin(), e = module->global_var_end();
			it != e; ++it) {
		auto& gv = *it;
		gv->accept(this);
	}
}

void BIRWriter::emitFunctions() {
	out << "Functions:" << std::endl;
	for (auto it = module->func_begin(), e = module->func_end();
			it != e; ++it) {
		auto& f = *it;
		f->accept(this);
	}
}

void BIRWriter::emitLabel(Statement* stmt) {
	if (stmt && stmt->hasLabel()) {
		emitIndent(2);
		out << stmt->getLabel() << ": (" << std::hex
				<< uint64_t(stmt) << std::dec << ")" << std::endl;
	}
	else if (stmt && stmt->isGotoTarget()) {
		emitIndent(2);
		out << "missing label for goto target: (" << std::hex
				<< uint64_t(stmt) << std::dec << ")" << std::endl;
	}
}

void BIRWriter::visit(GlobalVarDef* varDef) {
	currIndent = 1;
	emitCurrentIndent();

	varDef->getVar()->accept(this);
	out << " = ";
	if (varDef->getInitializer()) {
		varDef->getInitializer()->accept(this);
	}
	else {
		out << "<UNINITIALIZED>";
	}
	out << std::endl;
}

void BIRWriter::visit(Function* func) {
	currIndent = 1;
	emitCurrentIndent();
	func->getAsVar()->accept(this);
	out << std::endl;

	++currIndent;
	emitCurrentIndent();
	out << "ret type   : ";
	func->getRetType()->accept(this);
	out << std::endl;

	emitCurrentIndent();
	out << "params     :" << std::endl;
	++currIndent;
	for (auto& p : func->getParams()) {
		emitCurrentIndent();
		p->accept(this);
		out << std::endl;
	}
	--currIndent;

	emitCurrentIndent();
	out << "locals     :" << std::endl;
	++currIndent;
	for (auto& l : func->getLocalVars()) {
		emitCurrentIndent();
		l->accept(this);
		out << std::endl;
	}
	--currIndent;

	emitCurrentIndent();
	out << "statements :" << std::endl;
	++currIndent;
	if (auto b = func->getBody()) {
		b->accept(this);
	}
	--currIndent;
	out << std::endl;
}

void BIRWriter::visit(AssignStmt* stmt) {
	emitLabel(stmt);
	emitCurrentIndent();
	stmt->getLhs()->accept(this);
	out << " = ";
	stmt->getRhs()->accept(this);
	out << std::endl;
	if (stmt->getSuccessor()) stmt->getSuccessor()->accept(this);
}

void BIRWriter::visit(BreakStmt* stmt) {
	emitLabel(stmt);
	emitCurrentIndent();
	out << "break" << std::endl;
	if (stmt->getSuccessor()) stmt->getSuccessor()->accept(this);
}

void BIRWriter::visit(CallStmt* stmt) {
	emitLabel(stmt);
	emitCurrentIndent();
	stmt->getCall()->accept(this);
	out << std::endl;
	if (stmt->getSuccessor()) stmt->getSuccessor()->accept(this);
}

void BIRWriter::visit(ContinueStmt* stmt) {
	emitLabel(stmt);
	emitCurrentIndent();
	out << "continue" << std::endl;
	if (stmt->getSuccessor()) stmt->getSuccessor()->accept(this);
}

void BIRWriter::visit(EmptyStmt* stmt) {
	emitLabel(stmt);
	emitCurrentIndent();
	out << "EmptyStmt" << std::endl;
	if (stmt->getSuccessor()) stmt->getSuccessor()->accept(this);
}

void BIRWriter::visit(ForLoopStmt* stmt) {
	emitLabel(stmt);
	emitCurrentIndent();
	out << "for (";
	stmt->getIndVar()->accept(this);
	out << " = ";
	stmt->getStartValue()->accept(this);
	out << "; ";
	stmt->getEndCond()->accept(this);
	out << "; ";
	stmt->getStep()->accept(this);
	out << ")" << std::endl;
	++currIndent;
	if (stmt->getBody()) {
		stmt->getBody()->accept(this);
	} else {
		emitCurrentIndent();
		out << "<empty_body>" << std::endl;
	}
	--currIndent;
	if (stmt->getSuccessor()) stmt->getSuccessor()->accept(this);
}

void BIRWriter::visit(UForLoopStmt* stmt) {
	emitLabel(stmt);
	emitCurrentIndent();
	out << "ufor (";
	stmt->getInit()->accept(this);
	out << "; ";
	stmt->getCond()->accept(this);
	out << "; ";
	stmt->getStep()->accept(this);
	out << ")" << std::endl;
	++currIndent;
	if (stmt->getBody()) {
		stmt->getBody()->accept(this);
	} else {
		emitCurrentIndent();
		out << "<empty_body>" << std::endl;
	}
	--currIndent;
	if (stmt->getSuccessor()) stmt->getSuccessor()->accept(this);
}

void BIRWriter::visit(GotoStmt* stmt) {
	emitLabel(stmt);
	emitCurrentIndent();
	out << "goto ";
	if (stmt->getTarget()) {
		if (stmt->getTarget()->hasLabel()) {
			out << stmt->getTarget()->getLabel();
		} else {
			out << "<undef_label>";
		}
		out << " (" << std::hex << uint64_t(stmt->getTarget())
				<< std::dec << ")" << std::endl;
	} else {
		out << "<undef_target>" << std::endl;
	}
	if (stmt->getSuccessor()) stmt->getSuccessor()->accept(this);
}

void BIRWriter::visit(IfStmt* stmt) {
	emitLabel(stmt);
	bool first = true;
	for (auto it = stmt->clause_begin(), e = stmt->clause_end(); it != e; ++it) {
		emitCurrentIndent();
		if (first) {
			first = false;
			out << "if (";
		} else {
			out << "else if (";
		}
		it->first->accept(this);
		out << ")" << std::endl;
		if (it->second) {
			++currIndent;
			it->second->accept(this);
			--currIndent;
		}
	}
	if (stmt->hasElseClause()) {
		emitCurrentIndent();
		out << "else" << std::endl;
		++currIndent;
		stmt->getElseClause()->accept(this);
		--currIndent;
	}
	if (stmt->getSuccessor()) stmt->getSuccessor()->accept(this);
}

void BIRWriter::visit(ReturnStmt* stmt) {
	emitLabel(stmt);
	emitCurrentIndent();
	out << "return ";
	if (stmt->hasRetVal()) {
		stmt->getRetVal()->accept(this);
	} else {
		out << "void";
	}
	out<< std::endl;
	if (stmt->getSuccessor()) stmt->getSuccessor()->accept(this);
}

void BIRWriter::visit(SwitchStmt* stmt) {
	emitLabel(stmt);
	emitCurrentIndent();
	out << "switch (";
	stmt->getControlExpr()->accept(this);
	out << ")" << std::endl;

	for (auto it = stmt->clause_begin(), e = stmt->clause_end(); it != e; ++it) {
		emitCurrentIndent();
		if (it->first) {
			out << "case ";
			it->first->accept(this);
		} else {
			out << "default";
		}
		out << ":" << std::endl;
		if (it->second) {
			++currIndent;
			it->second->accept(this);
			--currIndent;
		}
	}
	if (stmt->getSuccessor()) stmt->getSuccessor()->accept(this);
}

void BIRWriter::visit(UnreachableStmt* stmt) {
	emitLabel(stmt);
	out << "unreachable" << std::endl;
	if (stmt->getSuccessor()) stmt->getSuccessor()->accept(this);
}

void BIRWriter::visit(VarDefStmt* stmt) {
	emitLabel(stmt);
	emitCurrentIndent();
	stmt->getVar()->accept(this);
	out << " = ";
	if (stmt->getInitializer()) {
		stmt->getInitializer()->accept(this);
		out << std::endl;
	} else {
		out << "undef" << std::endl;
	}
	if (stmt->getSuccessor()) stmt->getSuccessor()->accept(this);
}

void BIRWriter::visit(WhileLoopStmt* stmt) {
	emitLabel(stmt);
	emitCurrentIndent();
	out << "while (";
	stmt->getCondition()->accept(this);
	out << ")" << std::endl;
	++currIndent;
	if (stmt->getBody()) {
		stmt->getBody()->accept(this);
	} else {
		emitCurrentIndent();
		out << "<empty_body>" << std::endl;
	}
	--currIndent;
	if (stmt->getSuccessor()) stmt->getSuccessor()->accept(this);
}

void BIRWriter::visit(AddOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	out << " + ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(AddressOpExpr* expr) {
	out << "&";
	expr->getOperand()->accept(this);
}

void BIRWriter::visit(AndOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	out << " && ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(ArrayIndexOpExpr* expr) {
	expr->getBase()->accept(this);
	out << "[";
	expr->getIndex()->accept(this);
	out << "]";
}

void BIRWriter::visit(AssignOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	out << " = ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(BitAndOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	out << " & ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(BitOrOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	out << " | ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(BitShlOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	out << " << ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(BitShrOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	out << " >> ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(BitXorOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	out << " ^ ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(CallExpr* expr) {
	expr->getCalledExpr()->accept(this);
	out << "(";
	bool first = true;
	for (auto a : expr->getArgs()) {
		if (first) {
			first = false;
		} else {
			out << ", ";
		}
		a->accept(this);
	}
	out << ")";
}

void BIRWriter::visit(CommaOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	out << " , ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(DerefOpExpr* expr) {
	out << "*";
	expr->getOperand()->accept(this);
}

void BIRWriter::visit(DivOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	out << " / ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(EqOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	out << " == ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(GtEqOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	out << " >= ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(GtOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	out << " > ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(LtEqOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	out << " <= ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(LtOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	out << " < ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(ModOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	out << " % ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(MulOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	out << " * ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(NegOpExpr* expr) {
	out << "-";
	expr->getOperand()->accept(this);
}

void BIRWriter::visit(NeqOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	out << " != ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(NotOpExpr* expr) {
	out << "!";
	expr->getOperand()->accept(this);
}

void BIRWriter::visit(OrOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	out << " || ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(StructIndexOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	out << ".";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(SubOpExpr* expr) {
	expr->getFirstOperand()->accept(this);
	out << " - ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(TernaryOpExpr* expr) {
	expr->getCondition()->accept(this);
	out << " ? ";
	expr->getTrueValue()->accept(this);
	out << " : ";
	expr->getFalseValue()->accept(this);
}

void BIRWriter::visit(Variable* var) {
	auto n = var->getName();
	auto in = var->getInitialName();

	var->getType()->accept(this);
	out << " " << n;
	if (!in.empty() && in != n) {
		out << " (" << in << ")";
	}
}

void BIRWriter::visit(BitCastExpr* expr) {
	out << "bitcast ";
	expr->getOperand()->accept(this);
	out << " to ";
	expr->getType()->accept(this);
}

void BIRWriter::visit(ExtCastExpr* expr) {
	if (expr->getVariant() == ExtCastExpr::Variant::ZExt) {
		out << "zext ";
	} else if (expr->getVariant() == ExtCastExpr::Variant::SExt) {
		out << "sext ";
	} else if (expr->getVariant() == ExtCastExpr::Variant::FPExt) {
		out << "fpext ";
	}
	expr->getOperand()->accept(this);
	out << " to ";
	expr->getType()->accept(this);
}

void BIRWriter::visit(FPToIntCastExpr* expr) {
	out << "fptoint ";
	expr->getOperand()->accept(this);
	out << " to ";
	expr->getType()->accept(this);
}

void BIRWriter::visit(IntToFPCastExpr* expr) {
	out << "inttofp ";
	expr->getOperand()->accept(this);
	out << " to ";
	expr->getType()->accept(this);
}

void BIRWriter::visit(IntToPtrCastExpr* expr) {
	out << "inttoptr ";
	expr->getOperand()->accept(this);
	out << " to ";
	expr->getType()->accept(this);
}

void BIRWriter::visit(PtrToIntCastExpr* expr) {
	out << "ptrtoint ";
	expr->getOperand()->accept(this);
	out << " to ";
	expr->getType()->accept(this);
}

void BIRWriter::visit(TruncCastExpr* expr) {
	out << "trunc ";
	expr->getOperand()->accept(this);
	out << " to ";
	expr->getType()->accept(this);
}

void BIRWriter::visit(ConstArray* constant) {
	constant->getType()->accept(this);
	out << " = [";
	bool first = false;
	for (auto v : constant->getInitializedValue()) {
		if (first) {
			first = false;
		} else {
			out << ", ";
		}
		v->accept(this);
	}
}

void BIRWriter::visit(ConstBool* constant) {
	out << (constant->isTrue() ? "True" : "False");
}

void BIRWriter::visit(ConstFloat* constant) {
	constant->getType()->accept(this);
	out << " " << constant->toString();
}

void BIRWriter::visit(ConstInt* constant) {
	constant->getType()->accept(this);
	out << " " << constant->toString();
}

void BIRWriter::visit(ConstNullPointer* constant) {
	out << "const ";
	constant->getType()->accept(this);
}

void BIRWriter::visit(ConstString* constant) {
	out << "const ";
	constant->getType()->accept(this);
}

void BIRWriter::visit(ConstStruct* constant) {
	out << "const ";
	constant->getType()->accept(this);
}

void BIRWriter::visit(ConstSymbol* constant) {
	out << "const " << constant->getName();
}

void BIRWriter::visit(ArrayType* type) {
	out << "[";
	for (auto d : type->getDimensions()) {
		out << d << "x";
	}
	type->getContainedType()->accept(this);
	out << "]";
}

void BIRWriter::visit(FloatType* type) {
	out << "float_" << type->getSize();
}

void BIRWriter::visit(IntType* type) {
	if (type->isUnsigned()) {
		out << "u";
	}
	out << "int_" << type->getSize();
}

void BIRWriter::visit(PointerType* type) {
	type->getContainedType()->accept(this);
	out << "*";
}

void BIRWriter::visit(StringType* type) {
	if (type->getCharSize() > 8) {
		out << "wide_string";
	} else {
		out << "string";
	}
}

void BIRWriter::visit(StructType* type) {
	out << type->getName();
}

void BIRWriter::visit(FunctionType* type) {
	type->getRetType()->accept(this);
	out << "(";
	bool first = true;
	for (auto it = type->param_begin(), e = type->param_end(); it != e; ++it) {
		if (first) {
			first = false;
		} else {
			out << ", ";
		}
		auto& p = *it;
		p->accept(this);
	}
	if (type->isVarArg()) {
		out << ", ...";
	}
	out << ")";
}

void BIRWriter::visit(VoidType* type) {
	out << "void";
}

void BIRWriter::visit(UnknownType* type) {
	out << "type_unknown";
}

} // namespace llvmir2hll
} // namespace retdec
