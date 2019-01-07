/**
* @file src/llvmir2hll/hll/bir_writer.h
* @brief Implementation of BIRWriter.
* @copyright (c) 2018 Avast Software, licensed under the MIT license
*/

#include <iostream>

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

namespace retdec {
namespace llvmir2hll {

BIRWriter::BIRWriter() {

}

BIRWriter::~BIRWriter() {

}

void BIRWriter::emit(ShPtr<Module> m) {
	module = m;

	emitGlobals();
	emitFunctions();
}

void BIRWriter::emitIndent(unsigned indent) {
	std::cout << std::string(indent, '\t');
}

void BIRWriter::emitCurrentIndent() {
	emitIndent(currIndent);
}

void BIRWriter::emitGlobals() {
	std::cout << "Global variables:" << std::endl;
	for (auto it = module->global_var_begin(), e = module->global_var_end();
			it != e; ++it) {
		auto& gv = *it;
		gv->accept(this);
	}
}

void BIRWriter::emitFunctions() {
	std::cout << "Functions:" << std::endl;
	for (auto it = module->func_begin(), e = module->func_end();
			it != e; ++it) {
		auto& f = *it;
		f->accept(this);
	}
}

void BIRWriter::emitLabel(ShPtr<Statement> stmt) {
	if (stmt && stmt->hasLabel()) {
		emitIndent(2);
		std::cout << stmt->getLabel() << ": (" << std::hex
				<< uint64_t(stmt.get()) << std::dec << ")" << std::endl;
	}
	else if (stmt && stmt->isGotoTarget()) {
		emitIndent(2);
		std::cout << "missing label for goto target: (" << std::hex
				<< uint64_t(stmt.get()) << std::dec << ")" << std::endl;
	}
}

void BIRWriter::visit(ShPtr<GlobalVarDef> varDef) {
	currIndent = 1;
	emitCurrentIndent();

	varDef->getVar()->accept(this);
	std::cout << " = ";
	varDef->getInitializer()->accept(this);
	std::cout << std::endl;
}

void BIRWriter::visit(ShPtr<Function> func) {
	currIndent = 1;
	emitCurrentIndent();
	func->getAsVar()->accept(this);
	std::cout << std::endl;

	++currIndent;
	emitCurrentIndent();
	std::cout << "ret type   : ";
	func->getRetType()->accept(this);
	std::cout << std::endl;

	emitCurrentIndent();
	std::cout << "params     :" << std::endl;
	++currIndent;
	for (auto& p : func->getParams()) {
		emitCurrentIndent();
		p->accept(this);
		std::cout << std::endl;
	}
	--currIndent;

	emitCurrentIndent();
	std::cout << "locals     :" << std::endl;
	++currIndent;
	for (auto& l : func->getLocalVars()) {
		emitCurrentIndent();
		l->accept(this);
		std::cout << std::endl;
	}
	--currIndent;

	emitCurrentIndent();
	std::cout << "statements :" << std::endl;
	++currIndent;
	if (auto b = func->getBody()) {
		b->accept(this);
	}
	--currIndent;
	std::cout << std::endl;
}

void BIRWriter::visit(ShPtr<AssignStmt> stmt) {
	emitLabel(stmt);
	emitCurrentIndent();
	stmt->getLhs()->accept(this);
	std::cout << " = ";
	stmt->getRhs()->accept(this);
	std::cout << std::endl;
	if (stmt->getSuccessor()) stmt->getSuccessor()->accept(this);
}

void BIRWriter::visit(ShPtr<BreakStmt> stmt) {
	emitLabel(stmt);
	emitCurrentIndent();
	std::cout << "break" << std::endl;
	if (stmt->getSuccessor()) stmt->getSuccessor()->accept(this);
}

void BIRWriter::visit(ShPtr<CallStmt> stmt) {
	emitLabel(stmt);
	emitCurrentIndent();
	stmt->getCall()->accept(this);
	std::cout << std::endl;
	if (stmt->getSuccessor()) stmt->getSuccessor()->accept(this);
}

void BIRWriter::visit(ShPtr<ContinueStmt> stmt) {
	emitLabel(stmt);
	emitCurrentIndent();
	std::cout << "continue" << std::endl;
	if (stmt->getSuccessor()) stmt->getSuccessor()->accept(this);
}

void BIRWriter::visit(ShPtr<EmptyStmt> stmt) {
	emitLabel(stmt);
	emitCurrentIndent();
	std::cout << "EmptyStmt" << std::endl;
	if (stmt->getSuccessor()) stmt->getSuccessor()->accept(this);
}

void BIRWriter::visit(ShPtr<ForLoopStmt> stmt) {
	emitLabel(stmt);
	emitCurrentIndent();
	std::cout << "for (";
	stmt->getIndVar()->accept(this);
	std::cout << " = ";
	stmt->getStartValue()->accept(this);
	std::cout << "; ";
	stmt->getEndCond()->accept(this);
	std::cout << "; ";
	stmt->getStep()->accept(this);
	std::cout << ")" << std::endl;
	++currIndent;
	if (stmt->getBody()) {
		stmt->getBody()->accept(this);
	} else {
		emitCurrentIndent();
		std::cout << "<empty_body>" << std::endl;
	}
	--currIndent;
	if (stmt->getSuccessor()) stmt->getSuccessor()->accept(this);
}

void BIRWriter::visit(ShPtr<UForLoopStmt> stmt) {
	emitLabel(stmt);
	emitCurrentIndent();
	std::cout << "ufor (";
	stmt->getInit()->accept(this);
	std::cout << "; ";
	stmt->getCond()->accept(this);
	std::cout << "; ";
	stmt->getStep()->accept(this);
	std::cout << ")" << std::endl;
	++currIndent;
	if (stmt->getBody()) {
		stmt->getBody()->accept(this);
	} else {
		emitCurrentIndent();
		std::cout << "<empty_body>" << std::endl;
	}
	--currIndent;
	if (stmt->getSuccessor()) stmt->getSuccessor()->accept(this);
}

void BIRWriter::visit(ShPtr<GotoStmt> stmt) {
	emitLabel(stmt);
	emitCurrentIndent();
	std::cout << "goto ";
	if (stmt->getTarget()) {
		if (stmt->getTarget()->hasLabel()) {
			std::cout << stmt->getTarget()->getLabel();
		} else {
			std::cout << "<undef_label>";
		}
		std::cout << " (" << std::hex << uint64_t(stmt->getTarget().get())
				<< std::dec << ")" << std::endl;
	} else {
		std::cout << "<undef_target>" << std::endl;
	}
	if (stmt->getSuccessor()) stmt->getSuccessor()->accept(this);
}

void BIRWriter::visit(ShPtr<IfStmt> stmt) {
	emitLabel(stmt);
	bool first = true;
	for (auto it = stmt->clause_begin(), e = stmt->clause_end(); it != e; ++it) {
		emitCurrentIndent();
		if (first) {
			first = false;
			std::cout << "if (";
		} else {
			std::cout << "else if (";
		}
		it->first->accept(this);
		std::cout << ")" << std::endl;
		if (it->second) {
			++currIndent;
			it->second->accept(this);
			--currIndent;
		}
	}
	if (stmt->hasElseClause()) {
		emitCurrentIndent();
		std::cout << "else" << std::endl;
		++currIndent;
		stmt->getElseClause()->accept(this);
		--currIndent;
	}
	if (stmt->getSuccessor()) stmt->getSuccessor()->accept(this);
}

void BIRWriter::visit(ShPtr<ReturnStmt> stmt) {
	emitLabel(stmt);
	emitCurrentIndent();
	std::cout << "return ";
	stmt->getRetVal()->accept(this);
	std::cout<< std::endl;
	if (stmt->getSuccessor()) stmt->getSuccessor()->accept(this);
}

void BIRWriter::visit(ShPtr<SwitchStmt> stmt) {
	emitLabel(stmt);
	emitCurrentIndent();
	std::cout << "switch (";
	stmt->getControlExpr()->accept(this);
	std::cout << ")" << std::endl;

	for (auto it = stmt->clause_begin(), e = stmt->clause_end(); it != e; ++it) {
		emitCurrentIndent();
		std::cout << "case ";
		it->first->accept(this);
		std::cout << ":" << std::endl;
		if (it->second) {
			++currIndent;
			it->second->accept(this);
			--currIndent;
		}
	}
	if (stmt->getSuccessor()) stmt->getSuccessor()->accept(this);
}

void BIRWriter::visit(ShPtr<UnreachableStmt> stmt) {
	emitLabel(stmt);
	std::cout << "unreachable" << std::endl;
	if (stmt->getSuccessor()) stmt->getSuccessor()->accept(this);
}

void BIRWriter::visit(ShPtr<VarDefStmt> stmt) {
	emitLabel(stmt);
	emitCurrentIndent();
	stmt->getVar()->accept(this);
	std::cout << " = ";
	if (stmt->getInitializer()) {
		stmt->getInitializer()->accept(this);
		std::cout << std::endl;
	} else {
		std::cout << "undef" << std::endl;
	}
	if (stmt->getSuccessor()) stmt->getSuccessor()->accept(this);
}

void BIRWriter::visit(ShPtr<WhileLoopStmt> stmt) {
	emitLabel(stmt);
	emitCurrentIndent();
	std::cout << "while (";
	stmt->getCondition()->accept(this);
	std::cout << ")" << std::endl;
	++currIndent;
	if (stmt->getBody()) {
		stmt->getBody()->accept(this);
	} else {
		emitCurrentIndent();
		std::cout << "<empty_body>" << std::endl;
	}
	--currIndent;
	if (stmt->getSuccessor()) stmt->getSuccessor()->accept(this);
}

void BIRWriter::visit(ShPtr<AddOpExpr> expr) {
	expr->getFirstOperand()->accept(this);
	std::cout << " + ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(ShPtr<AddressOpExpr> expr) {
	std::cout << "&";
	expr->getOperand()->accept(this);
}

void BIRWriter::visit(ShPtr<AndOpExpr> expr) {
	expr->getFirstOperand()->accept(this);
	std::cout << " && ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(ShPtr<ArrayIndexOpExpr> expr) {
	expr->getBase()->accept(this);
	std::cout << "[";
	expr->getIndex()->accept(this);
	std::cout << "]";
}

void BIRWriter::visit(ShPtr<AssignOpExpr> expr) {
	expr->getFirstOperand()->accept(this);
	std::cout << " = ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(ShPtr<BitAndOpExpr> expr) {
	expr->getFirstOperand()->accept(this);
	std::cout << " & ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(ShPtr<BitOrOpExpr> expr) {
	expr->getFirstOperand()->accept(this);
	std::cout << " | ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(ShPtr<BitShlOpExpr> expr) {
	expr->getFirstOperand()->accept(this);
	std::cout << " << ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(ShPtr<BitShrOpExpr> expr) {
	expr->getFirstOperand()->accept(this);
	std::cout << " >> ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(ShPtr<BitXorOpExpr> expr) {
	expr->getFirstOperand()->accept(this);
	std::cout << " ^ ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(ShPtr<CallExpr> expr) {
	expr->getCalledExpr()->accept(this);
	std::cout << "(";
	bool first = true;
	for (auto a : expr->getArgs()) {
		if (first) {
			first = false;
		} else {
			std::cout << ", ";
		}
		a->accept(this);
	}
	std::cout << ")";
}

void BIRWriter::visit(ShPtr<CommaOpExpr> expr) {
	expr->getFirstOperand()->accept(this);
	std::cout << " , ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(ShPtr<DerefOpExpr> expr) {
	std::cout << "*";
	expr->getOperand()->accept(this);
}

void BIRWriter::visit(ShPtr<DivOpExpr> expr) {
	expr->getFirstOperand()->accept(this);
	std::cout << " / ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(ShPtr<EqOpExpr> expr) {
	expr->getFirstOperand()->accept(this);
	std::cout << " == ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(ShPtr<GtEqOpExpr> expr) {
	expr->getFirstOperand()->accept(this);
	std::cout << " >= ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(ShPtr<GtOpExpr> expr) {
	expr->getFirstOperand()->accept(this);
	std::cout << " > ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(ShPtr<LtEqOpExpr> expr) {
	expr->getFirstOperand()->accept(this);
	std::cout << " <= ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(ShPtr<LtOpExpr> expr) {
	expr->getFirstOperand()->accept(this);
	std::cout << " < ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(ShPtr<ModOpExpr> expr) {
	expr->getFirstOperand()->accept(this);
	std::cout << " % ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(ShPtr<MulOpExpr> expr) {
	expr->getFirstOperand()->accept(this);
	std::cout << " * ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(ShPtr<NegOpExpr> expr) {
	std::cout << "-";
	expr->getOperand()->accept(this);
}

void BIRWriter::visit(ShPtr<NeqOpExpr> expr) {
	expr->getFirstOperand()->accept(this);
	std::cout << " != ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(ShPtr<NotOpExpr> expr) {
	std::cout << "!";
	expr->getOperand()->accept(this);
}

void BIRWriter::visit(ShPtr<OrOpExpr> expr) {
	expr->getFirstOperand()->accept(this);
	std::cout << " || ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(ShPtr<StructIndexOpExpr> expr) {
	expr->getFirstOperand()->accept(this);
	std::cout << ".";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(ShPtr<SubOpExpr> expr) {
	expr->getFirstOperand()->accept(this);
	std::cout << " - ";
	expr->getSecondOperand()->accept(this);
}

void BIRWriter::visit(ShPtr<TernaryOpExpr> expr) {
	expr->getCondition()->accept(this);
	std::cout << " ? ";
	expr->getTrueValue()->accept(this);
	std::cout << " : ";
	expr->getFalseValue()->accept(this);
}

void BIRWriter::visit(ShPtr<Variable> var) {
	auto n = var->getName();
	auto in = var->getInitialName();

	var->getType()->accept(this);
	std::cout << " " << n;
	if (!in.empty() && in != n) {
		std::cout << " (" << in << ")";
	}
}

void BIRWriter::visit(ShPtr<BitCastExpr> expr) {
	std::cout << "bitcast ";
	expr->getOperand()->accept(this);
	std::cout << " to ";
	expr->getType()->accept(this);
}

void BIRWriter::visit(ShPtr<ExtCastExpr> expr) {
	if (expr->getVariant() == ExtCastExpr::Variant::ZExt) {
		std::cout << "zext ";
	} else if (expr->getVariant() == ExtCastExpr::Variant::SExt) {
		std::cout << "sext ";
	} else if (expr->getVariant() == ExtCastExpr::Variant::FPExt) {
		std::cout << "fpext ";
	}
	expr->getOperand()->accept(this);
	std::cout << " to ";
	expr->getType()->accept(this);
}

void BIRWriter::visit(ShPtr<FPToIntCastExpr> expr) {
	std::cout << "fptoint ";
	expr->getOperand()->accept(this);
	std::cout << " to ";
	expr->getType()->accept(this);
}

void BIRWriter::visit(ShPtr<IntToFPCastExpr> expr) {
	std::cout << "inttofp ";
	expr->getOperand()->accept(this);
	std::cout << " to ";
	expr->getType()->accept(this);
}

void BIRWriter::visit(ShPtr<IntToPtrCastExpr> expr) {
	std::cout << "inttoptr ";
	expr->getOperand()->accept(this);
	std::cout << " to ";
	expr->getType()->accept(this);
}

void BIRWriter::visit(ShPtr<PtrToIntCastExpr> expr) {
	std::cout << "ptrtoint ";
	expr->getOperand()->accept(this);
	std::cout << " to ";
	expr->getType()->accept(this);
}

void BIRWriter::visit(ShPtr<TruncCastExpr> expr) {
	std::cout << "trunc ";
	expr->getOperand()->accept(this);
	std::cout << " to ";
	expr->getType()->accept(this);
}

void BIRWriter::visit(ShPtr<ConstArray> constant) {
	constant->getType()->accept(this);
	std::cout << " = [";
	bool first = false;
	for (auto v : constant->getInitializedValue()) {
		if (first) {
			first = false;
		} else {
			std::cout << ", ";
		}
		v->accept(this);
	}
}

void BIRWriter::visit(ShPtr<ConstBool> constant) {
	std::cout << (constant->isTrue() ? "True" : "False");
}

void BIRWriter::visit(ShPtr<ConstFloat> constant) {
	constant->getType()->accept(this);
	std::cout << " " << constant->toString();
}

void BIRWriter::visit(ShPtr<ConstInt> constant) {
	constant->getType()->accept(this);
	std::cout << " " << constant->toString();
}

void BIRWriter::visit(ShPtr<ConstNullPointer> constant) {
	std::cout << "const ";
	constant->getType()->accept(this);
}

void BIRWriter::visit(ShPtr<ConstString> constant) {
	std::cout << "const ";
	constant->getType()->accept(this);
}

void BIRWriter::visit(ShPtr<ConstStruct> constant) {
	std::cout << "const ";
	constant->getType()->accept(this);
}

void BIRWriter::visit(ShPtr<ConstSymbol> constant) {
	std::cout << "const " << constant->getName();
}

void BIRWriter::visit(ShPtr<ArrayType> type) {
	std::cout << "[";
	for (auto d : type->getDimensions()) {
		std::cout << d << "x";
	}
	type->getContainedType()->accept(this);
	std::cout << "]";
}

void BIRWriter::visit(ShPtr<FloatType> type) {
	std::cout << "float_" << type->getSize();
}

void BIRWriter::visit(ShPtr<IntType> type) {
	if (type->isUnsigned()) {
		std::cout << "u";
	}
	std::cout << "int_" << type->getSize();
}

void BIRWriter::visit(ShPtr<PointerType> type) {
	type->getContainedType()->accept(this);
	std::cout << "*";
}

void BIRWriter::visit(ShPtr<StringType> type) {
	if (type->getCharSize() > 8) {
		std::cout << "wide_string";
	} else {
		std::cout << "string";
	}
}

void BIRWriter::visit(ShPtr<StructType> type) {
	std::cout << type->getName();
}

void BIRWriter::visit(ShPtr<FunctionType> type) {
	type->getRetType()->accept(this);
	std::cout << "(";
	bool first = true;
	for (auto it = type->param_begin(), e = type->param_end(); it != e; ++it) {
		if (first) {
			first = false;
		} else {
			std::cout << ", ";
		}
		auto& p = *it;
		p->accept(this);
	}
	if (type->isVarArg()) {
		std::cout << ", ...";
	}
	std::cout << ")";
}

void BIRWriter::visit(ShPtr<VoidType> type) {
	std::cout << "void";
}

void BIRWriter::visit(ShPtr<UnknownType> type) {
	std::cout << "type_unknown";
}


} // namespace llvmir2hll
} // namespace retdec
