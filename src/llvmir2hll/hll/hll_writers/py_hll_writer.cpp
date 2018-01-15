/**
* @file src/llvmir2hll/hll/hll_writers/py_hll_writer.cpp
* @brief Implementation of PyHLLWriter.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <sstream>

#include "retdec/llvmir2hll/analysis/written_into_globals_visitor.h"
#include "retdec/llvmir2hll/hll/bracket_managers/no_bracket_manager.h"
#include "retdec/llvmir2hll/hll/bracket_managers/py_bracket_manager.h"
#include "retdec/llvmir2hll/hll/compound_op_manager.h"
#include "retdec/llvmir2hll/hll/compound_op_managers/no_compound_op_manager.h"
#include "retdec/llvmir2hll/hll/compound_op_managers/py_compound_op_manager.h"
#include "retdec/llvmir2hll/hll/hll_writer_factory.h"
#include "retdec/llvmir2hll/hll/hll_writers/py_hll_writer.h"
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
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/llvmir2hll/utils/ir.h"

namespace retdec {
namespace llvmir2hll {

REGISTER_AT_FACTORY("py", PY_HLL_WRITER_ID, HLLWriterFactory, PyHLLWriter::create);

namespace {
/// Prefix of comments in Python.
const std::string COMMENT_PREFIX = "#";
}

/**
* @brief Constructs a new Python' writer.
*
* See create() for the description of parameters.
*/
PyHLLWriter::PyHLLWriter(llvm::raw_ostream &out):
	HLLWriter(out) {}

/**
* @brief Creates a new Python' writer.
*
* @param[in] out Output stream into which the HLL code will be emitted.
*/
ShPtr<HLLWriter> PyHLLWriter::create(llvm::raw_ostream &out) {
	return ShPtr<HLLWriter>(new PyHLLWriter(out));
}

std::string PyHLLWriter::getId() const {
	return PY_HLL_WRITER_ID;
}

std::string PyHLLWriter::getCommentPrefix() {
	return COMMENT_PREFIX;
}

bool PyHLLWriter::emitExternalFunction(ShPtr<Function> func) {
	std::ostringstream funcDecl;
	auto funcDeclString = module->getDeclarationStringForFunc(func);
	if (!funcDeclString.empty()) {
		funcDecl << funcDeclString;
	} else {
		funcDecl << func->getName() << "()";
	}
	out << getCurrentIndent() << comment(funcDecl.str()) << "\n";
	return true;
}

bool PyHLLWriter::emitFileFooter() {
	// If there is a function named main(), emit an entry point for the
	// program.
	for (auto i = module->func_definition_begin(),
			e = module->func_definition_end(); i != e; ++i) {
		if (module->isMainFunc(*i)) {
			emitEntryPoint(*i);
			return true;
		}
	}
	return false;
}

bool PyHLLWriter::emitTargetCode(ShPtr<Module> module) {
	if (optionKeepAllBrackets) {
		bracketsManager = ShPtr<BracketManager>(new NoBracketManager(module));
	} else {
		bracketsManager = ShPtr<BracketManager>(new PyBracketManager(module));
	}

	if (optionUseCompoundOperators) {
		compoundOpManager = ShPtr<CompoundOpManager>(new PyCompoundOpManager());
	} else {
		compoundOpManager = ShPtr<CompoundOpManager>(new NoCompoundOpManager());
	}

	return HLLWriter::emitTargetCode(module);
}

void PyHLLWriter::visit(ShPtr<GlobalVarDef> varDef) {
	out << getCurrentIndent();
	ShPtr<Variable> var(varDef->getVar());
	var->accept(this);
	out << " = ";
	if (ShPtr<Expression> init = varDef->getInitializer()) {
		emitConstantsInStructuredWay = true;
		init->accept(this);
		emitConstantsInStructuredWay = false;
	} else {
		// We have to emit the default initializer for the variable's type
		// because simply emitting the variable's name is not enough in Python.
		emitDefaultInitializer(var->getType());
	}

	tryEmitVarInfoInComment(var);

	out << "\n";
}

void PyHLLWriter::visit(ShPtr<Function> func) {
	if (func->isDeclaration()) {
		emitExternalFunction(func);
	} else {
		emitFunctionDefinition(func);
	}
}

void PyHLLWriter::visit(ShPtr<Variable> var) {
	out << var->getName();
}

void PyHLLWriter::visit(ShPtr<AddressOpExpr> expr) {
	emitUnaryOpExpr("&", expr);
}

void PyHLLWriter::visit(ShPtr<AssignOpExpr> expr) {
	emitBinaryOpExpr(" = ", expr);
}

void PyHLLWriter::visit(ShPtr<ArrayIndexOpExpr> expr) {
	// Base.
	emitExprWithBracketsIfNeeded(expr->getBase());

	// Access.
	out << "[";
	expr->getIndex()->accept(this);
	out << "]";
}

void PyHLLWriter::visit(ShPtr<StructIndexOpExpr> expr) {
	// Base.
	emitExprWithBracketsIfNeeded(expr->getFirstOperand());

	// Access + element.
	out << "['";
	expr->getSecondOperand()->accept(this);
	out << "']";
}

void PyHLLWriter::visit(ShPtr<DerefOpExpr> expr) {
	emitUnaryOpExpr("*", expr);
}

void PyHLLWriter::visit(ShPtr<NotOpExpr> expr) {
	emitUnaryOpExpr("not ", expr);
}

void PyHLLWriter::visit(ShPtr<NegOpExpr> expr) {
	emitUnaryOpExpr("-", expr);
}

void PyHLLWriter::visit(ShPtr<EqOpExpr> expr) {
	emitBinaryOpExpr(" == ", expr);
}

void PyHLLWriter::visit(ShPtr<NeqOpExpr> expr) {
	emitBinaryOpExpr(" != ", expr);
}

void PyHLLWriter::visit(ShPtr<LtOpExpr> expr) {
	emitBinaryOpExpr(" < ", expr);
}

void PyHLLWriter::visit(ShPtr<GtOpExpr> expr) {
	emitBinaryOpExpr(" > ", expr);
}

void PyHLLWriter::visit(ShPtr<LtEqOpExpr> expr) {
	emitBinaryOpExpr(" <= ", expr);
}

void PyHLLWriter::visit(ShPtr<GtEqOpExpr> expr) {
	emitBinaryOpExpr(" >= ", expr);
}

void PyHLLWriter::visit(ShPtr<TernaryOpExpr> expr) {
	bool bracketsAreNeeded = bracketsManager->areBracketsNeeded(expr);
	if (bracketsAreNeeded) {
		out << "(";
	}
	expr->getTrueValue()->accept(this);
	out << " if ";
	expr->getCondition()->accept(this);
	out << " else ";
	expr->getFalseValue()->accept(this);
	if (bracketsAreNeeded) {
		out << ")";
	}
}

void PyHLLWriter::visit(ShPtr<AddOpExpr> expr) {
	emitBinaryOpExpr(" + ", expr);
}

void PyHLLWriter::visit(ShPtr<SubOpExpr> expr) {
	emitBinaryOpExpr(" - ", expr);
}

void PyHLLWriter::visit(ShPtr<MulOpExpr> expr) {
	emitBinaryOpExpr(" * ", expr);
}

void PyHLLWriter::visit(ShPtr<ModOpExpr> expr) {
	emitBinaryOpExpr(" % ", expr);
}

void PyHLLWriter::visit(ShPtr<DivOpExpr> expr) {
	emitBinaryOpExpr(" / ", expr);
}

void PyHLLWriter::visit(ShPtr<AndOpExpr> expr) {
	emitBinaryOpExpr(" and ", expr);
}

void PyHLLWriter::visit(ShPtr<OrOpExpr> expr) {
	emitBinaryOpExpr(" or ", expr);
}

void PyHLLWriter::visit(ShPtr<BitAndOpExpr> expr) {
	emitBinaryOpExpr(" & ", expr);
}

void PyHLLWriter::visit(ShPtr<BitOrOpExpr> expr) {
	emitBinaryOpExpr(" | ", expr);
}

void PyHLLWriter::visit(ShPtr<BitXorOpExpr> expr) {
	emitBinaryOpExpr(" ^ ", expr);
}

void PyHLLWriter::visit(ShPtr<BitShlOpExpr> expr) {
	emitBinaryOpExpr(" << ", expr);
}

void PyHLLWriter::visit(ShPtr<BitShrOpExpr> expr) {
	// Recall that the right shift operator in Python is arithmetical. If the
	// shift is logical, we have to emit a custom function.
	if (expr->isArithmetical()) {
		emitBinaryOpExpr(" >> ", expr);
	} else {
		out << "lshr(";
		expr->getFirstOperand()->accept(this);
		out << ", ";
		expr->getSecondOperand()->accept(this);
		out << ")";
	}
}

void PyHLLWriter::visit(ShPtr<CallExpr> expr) {
	// Called expression.
	emitExprWithBracketsIfNeeded(expr->getCalledExpr());

	// Arguments.
	out << "(";
	emitSequenceWithAccept(expr->getArgs(), ", ");
	out << ")";
}

void PyHLLWriter::visit(ShPtr<CommaOpExpr> expr) {
	emitBinaryOpExpr(", ", expr);
}

// Casts -- we ignore them in this HLL.
void PyHLLWriter::visit(ShPtr<BitCastExpr> expr) {
	emitOperandOfCast(expr);
}

void PyHLLWriter::visit(ShPtr<ExtCastExpr> expr) {
	emitOperandOfCast(expr);
}

void PyHLLWriter::visit(ShPtr<TruncCastExpr> expr) {
	emitOperandOfCast(expr);
}

void PyHLLWriter::visit(ShPtr<FPToIntCastExpr> expr) {
	emitOperandOfCast(expr);
}

void PyHLLWriter::visit(ShPtr<IntToFPCastExpr> expr) {
	emitOperandOfCast(expr);
}

void PyHLLWriter::visit(ShPtr<IntToPtrCastExpr> expr) {
	emitOperandOfCast(expr);
}

void PyHLLWriter::visit(ShPtr<PtrToIntCastExpr> expr) {
	emitOperandOfCast(expr);
}
// End of casts.

void PyHLLWriter::visit(ShPtr<ConstBool> constant) {
	out << (constant->getValue() ? "True" : "False");
}

void PyHLLWriter::visit(ShPtr<ConstFloat> constant) {
	ConstFloat::Type value(constant->getValue());
	// Special values, like inf or nan, have to treated specifically.
	if (value.isInfinity() || value.isNaN()) {
		out << "float('";
		out << constant->toString();
		out << "')";
	} else {
		out << constant->toMostReadableString();
	}
}

void PyHLLWriter::visit(ShPtr<ConstInt> constant) {
	if (shouldBeEmittedInHexa(constant)) {
		out << constant->toString(16, "0x");
	} else {
		out << constant->toString();
	}
}

void PyHLLWriter::visit(ShPtr<ConstNullPointer> constant) {
	out << getConstNullPointerTextRepr();
}

void PyHLLWriter::visit(ShPtr<ConstString> constant) {
	// Contrary to C, in Python, we emit wide string literals the same way we
	// emit 8-bit string literals.
	out << "\"";
	out << constant->getValueAsEscapedCString();
	out << "\"";
}

void PyHLLWriter::visit(ShPtr<ConstArray> constant) {
	if (constant->isInitialized()) {
		emitInitializedConstArray(constant);
	} else {
		emitUninitializedConstArray(constant);
	}
}

void PyHLLWriter::visit(ShPtr<ConstStruct> constant) {
	bool emitInStructuredWay = shouldBeEmittedInStructuredWay(constant);

	out << "{";
	if (emitInStructuredWay) {
		out << "\n";
		increaseIndentLevel();
		out << getCurrentIndent();
	}

	ConstStruct::Type value(constant->getValue());
	bool first = true;
	for (const auto &member : value) {
		if (!first) {
			if (emitInStructuredWay) {
				out << ",\n" << getCurrentIndent();
			} else {
				out << ", ";
			}
		}

		out << "'";
		member.first->accept(this);
		out << "': ";
		member.second->accept(this);
		first = false;
	}

	if (emitInStructuredWay) {
		out << "\n";
		decreaseIndentLevel();
		out << getCurrentIndent();
	}
	out << "}";
}

void PyHLLWriter::visit(ShPtr<ConstSymbol> constant) {
	out << constant->getName();
}

void PyHLLWriter::visit(ShPtr<AssignStmt> stmt) {
	CompoundOpManager::CompoundOp compoundOp(
		compoundOpManager->tryOptimizeToCompoundOp(stmt));
	out << getCurrentIndent();
	stmt->getLhs()->accept(this);
	out << " " << compoundOp.getOperator() << " ";

	emitConstantsInStructuredWay = true;
	compoundOp.getOperand()->accept(this);
	emitConstantsInStructuredWay = false;

	out << "\n";
}

void PyHLLWriter::visit(ShPtr<VarDefStmt> stmt) {
	// Emit the definition statement only if there is an initializer;
	// otherwise, it makes no sense (recall that in Python, no declarations are
	// needed).
	ShPtr<Expression> init(stmt->getInitializer());
	if (!init) {
		return;
	}

	out << getCurrentIndent();
	stmt->getVar()->accept(this);
	out << " = ";

	emitConstantsInStructuredWay = true;
	init->accept(this);
	emitConstantsInStructuredWay = false;

	tryEmitVarInfoInComment(stmt->getVar());

	out << "\n";
}

void PyHLLWriter::visit(ShPtr<CallStmt> stmt) {
	out << getCurrentIndent();
	stmt->getCall()->accept(this);
	out << "\n";
}

void PyHLLWriter::visit(ShPtr<ReturnStmt> stmt) {
	out << getCurrentIndent() << "return";
	if (ShPtr<Expression> retVal = stmt->getRetVal()) {
		out << " ";
		retVal->accept(this);
	}
	out << "\n";
}

void PyHLLWriter::visit(ShPtr<EmptyStmt> stmt) {
	// Nada nada nada.
}

void PyHLLWriter::visit(ShPtr<IfStmt> stmt) {
	// Emit the first if clause and other else-if clauses (if any).
	for (auto i = stmt->clause_begin(), e = stmt->clause_end(); i != e; ++i) {
		out << getCurrentIndent();
		out << (i == stmt->clause_begin() ? "if " : "elif ");
		i->first->accept(this);
		out << ":\n";
		emitBody(i->second);
	}

	// Emit the else clause (if any).
	if (stmt->hasElseClause()) {
		out << getCurrentIndent() << "else:\n";
		emitBody(stmt->getElseClause());
	}
}

void PyHLLWriter::visit(ShPtr<SwitchStmt> stmt) {
	out << getCurrentIndent();
	out << "switch ";
	stmt->getControlExpr()->accept(this);
	out << ":\n";
	increaseIndentLevel();
	for (auto i = stmt->clause_begin(), e = stmt->clause_end(); i != e; ++i) {
		out << getCurrentIndent();
		if (i->first) {
			out << "case ";
			i->first->accept(this);
			out<< ":\n";
			emitBlock(i->second);
		} else {
			out << "default:\n";
			emitBlock(i->second);
		}
	}
	decreaseIndentLevel();
}

void PyHLLWriter::visit(ShPtr<WhileLoopStmt> stmt) {
	out << getCurrentIndent() << "while ";
	stmt->getCondition()->accept(this);
	out << ":\n";
	emitBody(stmt->getBody());
}

void PyHLLWriter::visit(ShPtr<ForLoopStmt> stmt) {
	out << getCurrentIndent() << "for ";
	stmt->getIndVar()->accept(this);
	out << " in range(";
	stmt->getStartValue()->accept(this);
	out << ", ";
	// If the end condition is of the form `i < x`, emit just `x`, otherwise
	// emit the complete condition.
	bool endCondEmitted = false;
	if (ShPtr<LtOpExpr> ltEndCond = cast<LtOpExpr>(stmt->getEndCond())) {
		if (stmt->getIndVar() == ltEndCond->getFirstOperand()) {
			ltEndCond->getSecondOperand()->accept(this);
			endCondEmitted = true;
		}
	}
	if (!endCondEmitted) {
		// TODO How to make this more pythonic?
		stmt->getEndCond()->accept(this);
	}
	// Emit step only if it differs from 1.
	ShPtr<ConstInt> stepInt = cast<ConstInt>(stmt->getStep());
	if (!stepInt || stepInt->getValue() != 1) {
		out << ", ";
		stmt->getStep()->accept(this);
	}
	out << "):\n";
	emitBody(stmt->getBody());
}

void PyHLLWriter::visit(ShPtr<UForLoopStmt> stmt) {
	FAIL("universal for loops are not supported in Python");
}

void PyHLLWriter::visit(ShPtr<BreakStmt> stmt) {
	out << getCurrentIndent() << "break\n";
}

void PyHLLWriter::visit(ShPtr<ContinueStmt> stmt) {
	out << getCurrentIndent() << "continue\n";
}

void PyHLLWriter::visit(ShPtr<GotoStmt> stmt) {
	out << getCurrentIndent() << "goto " << getGotoLabel(stmt->getTarget()) << "\n";
}

void PyHLLWriter::visit(ShPtr<UnreachableStmt> stmt) {
	out << getCurrentIndent() << comment("UNREACHABLE") << "\n";
}

void PyHLLWriter::visit(ShPtr<FloatType> type) {
	// Emit the default initializer.
	out << "0.0";
}

void PyHLLWriter::visit(ShPtr<IntType> type) {
	// Emit the default initializer.
	out << "0";
}

void PyHLLWriter::visit(ShPtr<PointerType> type) {
	// Emit the default initializer.
	out << getConstNullPointerTextRepr();
}

void PyHLLWriter::visit(ShPtr<StringType> type) {
	// Emit the default initializer.
	out << "\"\"";
}

void PyHLLWriter::visit(ShPtr<ArrayType> type) {
	// Emit the default initializer.
	out << "array(";
	bool first = true;
	for (const auto &dim : type->getDimensions()) {
		if (!first) {
			out << ", ";
		}
		out << dim;
		first = false;
	}
	out << ")";
}

void PyHLLWriter::visit(ShPtr<StructType> type) {
	// Emit the default initializer.
	out << "{";
	unsigned structElementIndex = 0;
	bool first = true;
	for (const auto &elementType : type->getElementTypes()) {
		if (!first) {
			out << ", ";
		}
		out << "'";
		out << structElementIndex++;
		out << "': ";
		elementType->accept(this);
		first = false;
	}
	out << "}";
}

void PyHLLWriter::visit(ShPtr<FunctionType> type) {
	// Emit the default initializer.
	out << "None";
}

void PyHLLWriter::visit(ShPtr<VoidType> type) {
	// Emit the default initializer.
	out << "None";
}

void PyHLLWriter::visit(ShPtr<UnknownType> type) {
	// Emit the default initializer.
	out << "None";
}

/**
* @brief Recursively emits the given block.
*
* @param[in] stmt Block to be emitted.
*
* Before emitting the block, the indentation level is increased. After the
* block is emitted, the indentation level is decreased.
*
* If a statement has some associated metadata, they're emitted in a comment
* before the statement.
*/
void PyHLLWriter::emitBlock(ShPtr<Statement> stmt) {
	increaseIndentLevel();

	// Emit the block, statement by statement.
	do {
		emitGotoLabelIfNeeded(stmt);

		// Are there any metadata?
		std::string metadata = stmt->getMetadata();
		if (!metadata.empty()) {
			emitDebugComment(metadata);
		}

		stmt->accept(this);
		stmt = stmt->getSuccessor();
	} while (stmt);

	decreaseIndentLevel();
}

/**
* @brief Emits the given function definition.
*
* @par Preconditions
*  - @a func is a function definition
*/
void PyHLLWriter::emitFunctionDefinition(ShPtr<Function> func) {
	PRECONDITION(func->isDefinition(), "it has to be a definition");

	out << getCurrentIndent() << "def " << func->getName() << "(";

	// Parameters
	emitSequenceWithAccept(func->getParams(), ", ");

	// Optional vararg indication.
	if (func->isVarArg()) {
		if (func->getNumOfParams() >= 1) {
			out << ", ";
		}
		out << "...";
	}

	out << "):\n";

	// Emit the function's body.
	emitGlobalDirectives(func);
	emitBlock(func->getBody());
}

/**
* @brief Emits <em>global</em> directives for all global variables used in the
*        given function.
*
* @par Preconditions
*  - @a func is a function definition
*
* The directives are emitted in a sorted way by the name of a variable
* (case insensitively).
*/
void PyHLLWriter::emitGlobalDirectives(ShPtr<Function> func) {
	PRECONDITION(func->isDefinition(), "it has to be a definition");

	increaseIndentLevel();

	// Obtain written-into global variables.
	VarSet writtenGlobalsSet(WrittenIntoGlobalsVisitor::getWrittenIntoGlobals(
		func, module));
	// Transform the set into a vector so we can sort the variables by their name.
	VarVector writtenGlobalsVector(writtenGlobalsSet.begin(), writtenGlobalsSet.end());
	sortByName(writtenGlobalsVector);

	// For each written-into global variable...
	for (const auto &var : writtenGlobalsVector) {
		// Emit the directive.
		out << getCurrentIndent() << "global ";
		var->accept(this);
		out << "\n";
	}

	decreaseIndentLevel();
}

/**
* @brief Emits the given debug comment.
*
* @param[in] comment Debug comment to be emitted.
* @param[in] indent If @c true, it indents the comment with @c getCurrentIndent().
*
* If @c optionEmitDebugComments is @c false, this function emits nothing. A new
* line is emitted after the comment.
*/
void PyHLLWriter::emitDebugComment(std::string comment, bool indent) {
	if (!optionEmitDebugComments) {
		// Debug comments are disabled.
		return;
	}

	if (indent) {
		out << getCurrentIndent();
	}
	out << this->comment(comment) << "\n";
}

/**
* @brief Emits the default initializer for the given type.
*/
void PyHLLWriter::emitDefaultInitializer(ShPtr<Type> type) {
	type->accept(this);
}

/**
* @brief Emits the given initialized array.
*
* @par Preconditions
*  - @a array is non-null and initialized
*
* When the @c emitConstantsInStructuredWay data member is set to @c true, the
* constant may be emitted in a structured way, i.e. spanning over multiple
* lines. Whether it is actually emitted in this way depends on the result of
* shouldBeEmittedInStructuredWay().
*/
void PyHLLWriter::emitInitializedConstArray(ShPtr<ConstArray> array) {
	if (shouldBeEmittedInStructuredWay(array)) {
		emitInitializedConstArrayInStructuredWay(array);
	} else {
		emitInitializedConstArrayInline(array);
	}
}

/**
* @brief Emits the given array inline.
*/
void PyHLLWriter::emitInitializedConstArrayInline(ShPtr<ConstArray> array) {
	// We emit the array in the following way (just an example):
	//
	//     arr = ["string1", "string2", "string3"]
	//
	out << "[";
	emitSequenceWithAccept(array->getInitializedValue(), ", ");
	out << "]";
}

/**
* @brief Emits the given array in a structured way (may span over multiple
*        lines).
*/
void PyHLLWriter::emitInitializedConstArrayInStructuredWay(ShPtr<ConstArray> array) {
	// We emit the array in the following way (just an example):
	//
	//     arr = [
	//         "string1",
	//         "string2",
	//         "string3"
	//     ]
	//
	out << "[\n";
	increaseIndentLevel();
	out << getCurrentIndent();
	emitSequenceWithAccept(array->getInitializedValue(),
		",\n" + getCurrentIndent());
	decreaseIndentLevel();
	out << getCurrentIndent();
	out << "\n]";
}

/**
* @brief Emits the given uninitialized array.
*
* @par Preconditions
*  - @a array is non-null and uninitialized
*/
void PyHLLWriter::emitUninitializedConstArray(ShPtr<ConstArray> array) {
	ArrayType::Dimensions dims(array->getDimensions());
	if (dims.empty()) {
		out << "[]";
		return;
	}

	// To prevent an emission of a lot of code, instead of emitting a
	// full-blown initializer, we emit just a call to array(). For example,
	// an initializer for an array of type `int [10][5][5]` is emitted as
	// `array(10, 5, 5)`.
	out << "array(";
	bool first = true;
	for (const auto &dim : dims) {
		if (!first) {
			out << ", ";
		}
		out << dim;
		first = false;
	}
	out << ")";
}

/**
* @brief Emits the operand of the given cast.
*/
void PyHLLWriter::emitOperandOfCast(ShPtr<CastExpr> expr) {
	expr->getOperand()->accept(this);
}

/**
* @brief Emits a label of @a stmt if it is needed.
*
* A label is needed if @a stmt is the target of a goto statement.
*/
void PyHLLWriter::emitGotoLabelIfNeeded(ShPtr<Statement> stmt) {
	if (stmt->isGotoTarget()) {
		out << getIndentForGotoLabel() << getGotoLabel(stmt) << ": # goto label\n";
	}
}

/**
* @brief Emits the given body of a loop/if statement.
*
* If the given body is empty, it emits @c pass instead of nothing so the
* output is valid. For example, instead of
* @code
* while getchar() != 10:
* @endcode
* we emit
* @code
* while getchar() != 10:
*     pass
* @endcode
* which is valid Python code.
*/
void PyHLLWriter::emitBody(ShPtr<Statement> body) {
	if (!body || !skipEmptyStmts(body)) {
		// The body is empty.
		increaseIndentLevel();
		out << getCurrentIndent() << "pass\n";
		decreaseIndentLevel();
	} else {
		// The body is non-empty.
		emitBlock(body);
	}
}

/**
* @brief Emits the entry point for the resulting code.
*
* @param[in] mainFunc The main() function.
*/
void PyHLLWriter::emitEntryPoint(ShPtr<Function> mainFunc) {
	emitSectionHeader("Entry Point");
	out << "\n";
	out << getCurrentIndent() << "if __name__ == '__main__':\n";
	increaseIndentLevel();
	out << getCurrentIndent() << "import sys\n";
	// If main() takes two arguments, call it with argc and argv;
	// otherwise, call it without any arguments.
	std::string mainFuncName(mainFunc->getName());
	out << getCurrentIndent() << "sys.exit(" << mainFuncName << "(";
	if (mainFunc->getParams().size() == 2) {
		out << "len(sys.argv), sys.argv";
	}
	out << "))\n";
	decreaseIndentLevel();
}

} // namespace llvmir2hll
} // namespace retdec
