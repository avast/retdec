/**
* @file src/llvmir2hll/hll/hll_writers/c_hll_writer.cpp
* @brief Implementation of CHLLWriter.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#include <cctype>
#include <set>
#include <sstream>

#include "retdec/llvmir2hll/analysis/indirect_func_ref_analysis.h"
#include "retdec/llvmir2hll/analysis/null_pointer_analysis.h"
#include "retdec/llvmir2hll/analysis/special_fp_analysis.h"
#include "retdec/llvmir2hll/analysis/used_types_visitor.h"
#include "retdec/llvmir2hll/hll/bracket_managers/c_bracket_manager.h"
#include "retdec/llvmir2hll/hll/bracket_managers/no_bracket_manager.h"
#include "retdec/llvmir2hll/hll/compound_op_manager.h"
#include "retdec/llvmir2hll/hll/compound_op_managers/c_compound_op_manager.h"
#include "retdec/llvmir2hll/hll/compound_op_managers/no_compound_op_manager.h"
#include "retdec/llvmir2hll/hll/hll_writer_factory.h"
#include "retdec/llvmir2hll/hll/hll_writers/c_hll_writer.h"
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
#include "retdec/llvmir2hll/semantics/semantics.h"
#include "retdec/llvmir2hll/support/debug.h"
#include "retdec/llvmir2hll/support/headers_for_declared_funcs.h"
#include "retdec/llvmir2hll/support/maybe.h"
#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/llvmir2hll/support/struct_types_sorter.h"
#include "retdec/llvmir2hll/support/types.h"
#include "retdec/llvmir2hll/utils/ir.h"
#include "retdec/llvm-support/diagnostics.h"
#include "retdec/utils/container.h"
#include "retdec/utils/conversion.h"

using namespace retdec::llvm_support;

using retdec::utils::addToSet;
using retdec::utils::toString;

namespace retdec {
namespace llvmir2hll {

REGISTER_AT_FACTORY("c", C_HLL_WRITER_ID, HLLWriterFactory, CHLLWriter::create);

namespace {
/// Prefix of comments in C.
const std::string COMMENT_PREFIX = "//";

/**
* @brief Returns a valid version of the given identifier.
*
* The resulting identifier is a proper C name.
*/
std::string validateIdentifier(const std::string &identifier) {
	std::string validIdentifier;

	// Replace all invalid characters with an underscore.
	for (std::size_t i = 0, e = identifier.size(); i != e; ++i) {
		char c = identifier[i];
		if (std::isalpha(c) || std::isdigit(c) || c == '_') {
			validIdentifier += c;
		} else {
			validIdentifier += '_';
		}
	}

	// Make sure that the first character is either a letter or an underscore.
	if (std::isdigit(validIdentifier[0])) {
		validIdentifier = '_' + validIdentifier;
	}

	return validIdentifier;
}

/**
* @brief Returns FunctionType from the given (possibly indirect) pointer to
*        FunctionType.
*
* If @a type is either not a pointer or it does not point to FunctionType, the
* null pointer is returned.
*/
ShPtr<FunctionType> getFuncTypeFromPointerToFunc(ShPtr<Type> type) {
	if (!isa<PointerType>(type)) {
		return ShPtr<FunctionType>();
	}

	ShPtr<Type> pointedType(type);
	while (ShPtr<PointerType> containedPointerType = cast<PointerType>(pointedType)) {
		pointedType = containedPointerType->getContainedType();
	}
	return cast<FunctionType>(pointedType);
}

/**
* @brief Returns @c true if @a type is a (possibly indirect) pointer to a
*        function, @c false otherwise.
*/
bool isPointerToFunc(ShPtr<Type> type) {
	return getFuncTypeFromPointerToFunc(type) != nullptr;
}

/**
* @brief Returns ArrayType from the given (possibly indirect) pointer to
*        ArrayType.
*
* If @a type is either not a pointer or it does not point to ArrayType, the
* null pointer is returned.
*/
ShPtr<ArrayType> getArrayTypeFromPointerToArray(ShPtr<Type> type) {
	if (!isa<PointerType>(type)) {
		return ShPtr<ArrayType>();
	}

	ShPtr<Type> pointedType(type);
	while (ShPtr<PointerType> containedPointerType = cast<PointerType>(pointedType)) {
		pointedType = containedPointerType->getContainedType();
	}
	return cast<ArrayType>(pointedType);
}

/**
* @brief Returns @c true if @a type is a (possibly indirect) pointer to an
*        array, @c false otherwise.
*/
bool isPointerToArray(ShPtr<Type> type) {
	return getArrayTypeFromPointerToArray(type) != nullptr;
}

/**
* @brief Returns @c true if @a type is an array of (possibly indirect) pointers
*        to functions, @c false otherwise.
*/
bool isArrayOfFuncPointers(ShPtr<Type> type) {
	ShPtr<ArrayType> arrayType(cast<ArrayType>(type));
	if (!arrayType) {
		return false;
	}

	return isPointerToFunc(arrayType->getContainedType());
}

/**
* @brief Returns @c true if the given expression is an uninitialized array, @c
*        false otherwise.
*/
bool isUninitializedConstArray(ShPtr<Expression> expr) {
	ShPtr<ConstArray> constArray(cast<ConstArray>(expr));
	return constArray && !constArray->isInitialized();
}

/**
* @brief Returns @c true if the given constant has only fields that should be
*        initialized as an uninitialized array, @c false otherwise.
*/
bool hasOnlyUninitializedConstArrayInits(ShPtr<ConstStruct> constant) {
	ConstStruct::Type value(constant->getValue());
	for (const auto &member : value) {
		if (!isUninitializedConstArray(member.second)) {
			return false;
		}
	}
	return true;
}

} // anonymous namespace

/**
* @brief Constructs a new C writer.
*
* See create() for the description of parameters.
*/
CHLLWriter::CHLLWriter(llvm::raw_ostream &out):
	HLLWriter(out), unnamedStructCounter(0), emittingGlobalVarDefs(false),
	optionEmitFunctionPrototypesForNonLibraryFuncs(false) {}

/**
* @brief Creates a new C writer.
*
* @param[in] out Output stream into which the HLL code will be emitted.
*/
ShPtr<HLLWriter> CHLLWriter::create(llvm::raw_ostream &out) {
	return ShPtr<HLLWriter>(new CHLLWriter(out));
}

std::string CHLLWriter::getId() const {
	return C_HLL_WRITER_ID;
}

std::string CHLLWriter::getCommentPrefix() {
	return COMMENT_PREFIX;
}

// File header contains includes, int and floating-point typedefs, and
// structure declarations.
bool CHLLWriter::emitFileHeader() {
	// Emit the standard header.
	if (HLLWriter::emitFileHeader()) { out << "\n"; }

	//
	// Header files
	//
	ShPtr<UsedTypes> usedTypes(UsedTypesVisitor::getUsedTypes(module));
	StringSet headerFiles;

	// If the module uses the bool type, we have to #include stdbool.h.
	if (usedTypes->isUsedBool()) {
		headerFiles.insert("stdbool.h");
	}

	// If the module uses special floating-point values, like infinity, we have
	// to #include math.h.
	if (SpecialFPAnalysis::hasSpecialFP(module)) {
		headerFiles.insert("math.h");
	}

	// If some integer type is used in the module, #include stdint.h.
	for (auto i = usedTypes->int_begin(), e = usedTypes->int_end();
			i != e; ++i) {
		if (cast<IntType>(*i)->getSize() > 1) {
			headerFiles.insert("stdint.h");
			break;
		}
	}

	// If the null pointer is used, #include stdlib.h (for the NULL macro).
	if (NullPointerAnalysis::useNullPointers(module)) {
		headerFiles.insert("stdlib.h");
	}

	// Include headers for linked functions.
	addToSet(HeadersForDeclaredFuncs::getHeaders(module), headerFiles);

	// Emit the header includes.
	for (const auto &file : headerFiles) {
		out << getCurrentIndent() << "#include <" << file << ">\n";
	}

	//
	// Integer typedefs
	//
	// The sets of unsupported integer bit widths in C99 and the nearest bigger type.
	// map<the unsupported bit width, the nearest bigger bit width>
	std::map<std::size_t, std::size_t> emitSignedInt, emitUnsignedInt;

	// Initialization of pointer and iterators to signed integer types.
	std::map<std::size_t, std::size_t> *emit = &emitSignedInt;
	auto it = usedTypes->signed_int_begin();
	auto et = usedTypes->signed_int_end();
	// Two iterations:
	// - the first is for signed integers
	// - the second is for unsigned integers
	for (int j = 0; j < 2 ; ++j) {
		// For all signed/unsigned integer types...
		for (; it != et; ++it) {
			std::size_t size = cast<IntType>(*it)->getSize();
			// Supported bit widths are ignored.
			if (size <= 1 || size == 8 || size == 16 || size == 32 || size == 64) {
				continue;
			// Saving to map bit width with the nearest bigger supported bit width.
			} else if (size < 8) {
				(*emit)[size] = 8;
			} else if (size < 16) {
				(*emit)[size] = 16;
			} else if (size < 32) {
				(*emit)[size] = 32;
			} else if (size < 64) {
				(*emit)[size] = 64;
			} else { // size > 64
				(*emit)[size] = 64;
			}
		}
		// Change the pointer and the iterators to unsigned integer types.
		emit = &emitUnsignedInt;
		it = usedTypes->unsigned_int_begin();
		et = usedTypes->unsigned_int_end();
	}

	// Emit integer typedefs.
	if (!emitSignedInt.empty() || !emitUnsignedInt.empty()) {
		out << "\n";
		emitSectionHeader("Integer Types Definitions");
		out << "\n";
	}
	// - signed
	for (const auto &p : emitSignedInt) {
		out << getCurrentIndent() << "typedef int" << p.second << "_t "
			<< "int" << p.first << "_t;\n";
	}
	// - unsigned
	for (const auto &p : emitUnsignedInt) {
		out << getCurrentIndent() << "typedef uint" << p.second << "_t "
			<< "uint" << p.first << "_t;\n";
	}

	//
	// Floating point typedefs
	//
	bool emitTypedefs = false;
	bool emitFloat32 = false;
	bool emitFloat64 = false;
	bool emitFloat80 = false;
	bool emitFloat128 = false;
	for (const auto &type : usedTypes->getFloatTypes()) {
		auto floatType = cast<FloatType>(type);
		if (floatType->getSize() == 32) {
			emitFloat32 = true;
		} else if (floatType->getSize() == 64) {
			emitFloat64 = true;
		} else if (floatType->getSize() == 80) {
			emitFloat80 = true;
		} else if (floatType->getSize() == 128) {
			emitFloat128 = true;
		} else {
			FAIL("unsupported floating-point type of size "
				<< floatType->getSize());
		}
		emitTypedefs = true;
	}
	// Emit them.
	if (emitTypedefs) {
		out << "\n";
		emitSectionHeader("Float Types Definitions");
		out << "\n";
	}
	if (emitFloat32) {
		out << getCurrentIndent() << "typedef float float32_t;\n";
	}
	if (emitFloat64) {
		out << getCurrentIndent() << "typedef double float64_t;\n";
	}
	if (emitFloat80) {
		out << getCurrentIndent() << "typedef long double float80_t;\n";
	}
	if (emitFloat128) {
		out << getCurrentIndent() << "typedef long double float128_t;\n";
	}

	//
	// Structures
	//
	// Obtain and sort the used structures by their dependencies.
	StructTypeVector usedStructTypes(StructTypesSorter::sort(
		usedTypes->getStructTypes()));
	// Make sure all structures have a name.
	for (const auto &type : usedStructTypes) {
		std::string structName(type->hasName() ?
			type->getName() : genNameForUnnamedStruct(usedStructTypes));
		structName = validateIdentifier(structName);
		structNames[type] = structName;
	}
	// Emit them.
	if (!usedStructTypes.empty()) {
		out << "\n";
		emitSectionHeader("Structures");
	}
	for (const auto &type : usedStructTypes) {
		out << "\n";
		emitStructDeclaration(type);
		out << ";\n";
	}

	return true;
}

bool CHLLWriter::emitGlobalVariables() {
	// See emitConstStruct() for a rationale behind setting the following
	// variable.
	emittingGlobalVarDefs = true;
	bool codeEmitted = HLLWriter::emitGlobalVariables();
	emittingGlobalVarDefs = false;
	return codeEmitted;
}

bool CHLLWriter::emitFunctionPrototypesHeader() {
	if (shouldEmitFunctionPrototypesHeader()) {
		emitSectionHeader("Function Prototypes");
		return true;
	}
	return false;
}

bool CHLLWriter::emitFunctionPrototypes() {
	bool somethingEmitted = false;

	somethingEmitted |= emitStandardFunctionPrototypes();

	if (optionEmitFunctionPrototypesForNonLibraryFuncs) {
		// Apart from the prototypes of the functions defined in the module,
		// emit prototypes for functions which do not have any associated
		// header file, i.e. which are probably not from a standard library.
		//
		// This is done to (1) prevent syntax checker from complaining about
		// the use of undefined variables, and (2) give us a hint that some
		// function may be from a standard library, but we do not have a header
		// for it.
		somethingEmitted |= emitFunctionPrototypesForNonLibraryFuncs();
	}

	return somethingEmitted;
}

bool CHLLWriter::emitExternalFunction(ShPtr<Function> func) {
	out << getCurrentIndent() << getCommentPrefix() << " ";
	auto funcDeclString = module->getDeclarationStringForFunc(func);
	if (!funcDeclString.empty()) {
			out << funcDeclString << "\n";
	} else {
			emitFunctionPrototype(func);
	}
	return true;
}

void CHLLWriter::visit(ShPtr<GlobalVarDef> varDef) {
	ShPtr<Variable> var(varDef->getVar());
	ShPtr<Expression> init(varDef->getInitializer());

	out << getCurrentIndent();
	emitVarWithType(var);

	// Initializer.
	if (init) {
		emitConstantsInStructuredWay = true;
		if (ShPtr<ConstArray> constArrayInit = cast<ConstArray>(init)) {
			if (constArrayInit->isInitialized()) {
				out << " = ";

				emitInitializedConstArray(constArrayInit);
			}
		} else if (ShPtr<ConstStruct> constStructInit = cast<ConstStruct>(init)) {
			out << " = ";

			// When defining a structure, we do not need to emit a cast.
			emitConstStruct(constStructInit, false);
		} else {
			out << " = ";
			init->accept(this);
		}
		emitConstantsInStructuredWay = false;
	}

	out << ";";

	tryEmitVarInfoInComment(var);

	out << "\n";
}

void CHLLWriter::visit(ShPtr<Function> func) {
	if (func->isDeclaration()) {
		emitFunctionPrototype(func);
	} else {
		emitFunctionDefinition(func);
	}
}

bool CHLLWriter::emitTargetCode(ShPtr<Module> module) {
	if (optionKeepAllBrackets) {
		bracketsManager = ShPtr<BracketManager>(new NoBracketManager(module));
	} else {
		bracketsManager = ShPtr<BracketManager>(new CBracketManager(module));
	}

	if (optionUseCompoundOperators) {
		compoundOpManager = ShPtr<CompoundOpManager>(new CCompoundOpManager());
	} else {
		compoundOpManager = ShPtr<CompoundOpManager>(new NoCompoundOpManager());
	}

	return HLLWriter::emitTargetCode(module);
}

void CHLLWriter::visit(ShPtr<Variable> var) {
	out << var->getName();
}

void CHLLWriter::visit(ShPtr<AddressOpExpr> expr) {
	emitUnaryOpExpr("&", expr);
}

void CHLLWriter::visit(ShPtr<AssignOpExpr> expr) {
	emitAssignment(expr->getFirstOperand(), expr->getSecondOperand());
}

void CHLLWriter::visit(ShPtr<ArrayIndexOpExpr> expr) {
	// Base.
	emitExprWithBracketsIfNeeded(expr->getBase());

	// Access.
	out << "[";
	expr->getIndex()->accept(this);
	out << "]";
}

void CHLLWriter::visit(ShPtr<StructIndexOpExpr> expr) {
	// Base.
	ShPtr<Expression> base(expr->getFirstOperand());
	emitExprWithBracketsIfNeeded(base);

	// Access.
	out << (isa<PointerType>(base->getType()) ? "->" : ".");

	// Element.
	out << "e";
	expr->getSecondOperand()->accept(this);
}

void CHLLWriter::visit(ShPtr<DerefOpExpr> expr) {
	emitUnaryOpExpr("*", expr);
}

void CHLLWriter::visit(ShPtr<NotOpExpr> expr) {
	emitUnaryOpExpr("!", expr);
}

void CHLLWriter::visit(ShPtr<NegOpExpr> expr) {
	emitUnaryOpExpr("-", expr);
}

void CHLLWriter::visit(ShPtr<EqOpExpr> expr) {
	emitBinaryOpExpr(" == ", expr);
}

void CHLLWriter::visit(ShPtr<NeqOpExpr> expr) {
	emitBinaryOpExpr(" != ", expr);
}

void CHLLWriter::visit(ShPtr<LtOpExpr> expr) {
	emitBinaryOpExpr(" < ", expr);
}

void CHLLWriter::visit(ShPtr<GtOpExpr> expr) {
	emitBinaryOpExpr(" > ", expr);
}

void CHLLWriter::visit(ShPtr<LtEqOpExpr> expr) {
	emitBinaryOpExpr(" <= ", expr);
}

void CHLLWriter::visit(ShPtr<GtEqOpExpr> expr) {
	emitBinaryOpExpr(" >= ", expr);
}

void CHLLWriter::visit(ShPtr<TernaryOpExpr> expr) {
	bool bracketsAreNeeded = bracketsManager->areBracketsNeeded(expr);
	if (bracketsAreNeeded) {
		out << "(";
	}
	expr->getCondition()->accept(this);
	out << " ? ";
	expr->getTrueValue()->accept(this);
	out << " : ";
	expr->getFalseValue()->accept(this);
	if (bracketsAreNeeded) {
		out << ")";
	}
}

void CHLLWriter::visit(ShPtr<AddOpExpr> expr) {
	emitBinaryOpExpr(" + ", expr);
}

void CHLLWriter::visit(ShPtr<SubOpExpr> expr) {
	emitBinaryOpExpr(" - ", expr);
}

void CHLLWriter::visit(ShPtr<MulOpExpr> expr) {
	emitBinaryOpExpr(" * ", expr);
}

void CHLLWriter::visit(ShPtr<ModOpExpr> expr) {
	emitBinaryOpExpr(" % ", expr);
}

void CHLLWriter::visit(ShPtr<DivOpExpr> expr) {
	emitBinaryOpExpr(" / ", expr);
}

void CHLLWriter::visit(ShPtr<AndOpExpr> expr) {
	emitBinaryOpExpr(" && ", expr);
}

void CHLLWriter::visit(ShPtr<OrOpExpr> expr) {
	emitBinaryOpExpr(" || ", expr);
}

void CHLLWriter::visit(ShPtr<BitAndOpExpr> expr) {
	emitBinaryOpExpr(" & ", expr);
}

void CHLLWriter::visit(ShPtr<BitOrOpExpr> expr) {
	emitBinaryOpExpr(" | ", expr);
}

void CHLLWriter::visit(ShPtr<BitXorOpExpr> expr) {
	emitBinaryOpExpr(" ^ ", expr);
}

void CHLLWriter::visit(ShPtr<BitShlOpExpr> expr) {
	emitBinaryOpExpr(" << ", expr);
}

void CHLLWriter::visit(ShPtr<BitShrOpExpr> expr) {
	// TODO Distinguish between logical and arithmetical shifts (recall that if
	// the first operand is of a signed type with a negative value, it is
	// implementation-defined whether >> is logical or arithmetical).
	emitBinaryOpExpr(" >> ", expr);
}

void CHLLWriter::visit(ShPtr<CallExpr> expr) {
	// Called expression.
	emitExprWithBracketsIfNeeded(expr->getCalledExpr());

	// Arguments.
	out << "(";
	emitSequenceWithAccept(expr->getArgs(), ", ");
	out << ")";
}

void CHLLWriter::visit(ShPtr<CommaOpExpr> expr) {
	emitBinaryOpExpr(", ", expr);
}

void CHLLWriter::visit(ShPtr<BitCastExpr> expr) {
	emitCastInStandardWay(expr);
}

void CHLLWriter::visit(ShPtr<ExtCastExpr> expr) {
	emitCastInStandardWay(expr);
}

void CHLLWriter::visit(ShPtr<TruncCastExpr> expr) {
	// Specific property, see the LLVM reference manual.
	if (isa<IntType>(expr->getType()) &&
			(cast<IntType>(expr->getType())->isBool())) {
		out << "(";
		expr->getOperand()->accept(this);
		out << "&1)";
	} else {
		emitCastInStandardWay(expr);
	}
}

void CHLLWriter::visit(ShPtr<FPToIntCastExpr> expr) {
	out << "(";
	ShPtr<IntType> type = cast<IntType>(expr->getType());
	if (type->isBool()) {
		out << "bool";
	} else {
		type->accept(this);
	}
	out << ")";
	expr->getOperand()->accept(this);
}

void CHLLWriter::visit(ShPtr<IntToFPCastExpr> expr) {
	emitCastInStandardWay(expr);
}

void CHLLWriter::visit(ShPtr<IntToPtrCastExpr> expr) {
	emitCastInStandardWay(expr);
}

void CHLLWriter::visit(ShPtr<PtrToIntCastExpr> expr) {
	emitCastInStandardWay(expr);
}

void CHLLWriter::visit(ShPtr<ConstBool> constant) {
	out << (constant->getValue() ? "true" : "false"); // from stdbool.h
}

void CHLLWriter::visit(ShPtr<ConstFloat> constant) {
	ConstFloat::Type value(constant->getValue());
	// Special values, like inf or nan, have to treated specifically.
	if (value.isInfinity()) {
		if (value.isNegative()) {
			out << "-";
		}
		out << "INFINITY"; // the constant from <math.h>
	} else if (value.isNaN()) {
		if (value.isNegative()) {
			out << "-";
		}
		out << "NAN"; // the constant from <math.h>
	} else {
		out << constant->toMostReadableString();
		emitConstFloatSuffixIfNeeded(constant);
	}
}

void CHLLWriter::visit(ShPtr<ConstInt> constant) {
	if (shouldBeEmittedInHexa(constant)) {
		out << constant->toString(16, "0x");
	} else {
		out << constant->toString();
	}
}

void CHLLWriter::visit(ShPtr<ConstNullPointer> constant) {
	out << getConstNullPointerTextRepr();
}

void CHLLWriter::visit(ShPtr<ConstString> constant) {
	if (constant->isWideString()) {
		out << "L";
	}

	out << "\"";
	out << constant->getValueAsEscapedCString();
	out << "\"";
}

void CHLLWriter::visit(ShPtr<ConstArray> constant) {
	if (constant->isInitialized()) {
		emitInitializedConstArray(constant);
	} else {
		emitUninitializedConstArray(constant);
	}
}

void CHLLWriter::visit(ShPtr<ConstStruct> constant) {
	emitConstStruct(constant);
}

void CHLLWriter::visit(ShPtr<ConstSymbol> constant) {
	out << constant->getName();
}

void CHLLWriter::visit(ShPtr<AssignStmt> stmt) {
	// Special treatment of constant arrays.
	if (ShPtr<ConstArray> constArray = cast<ConstArray>(stmt->getRhs())) {
		if (!constArray->isInitialized()) {
			return;
		}
	}

	out << getCurrentIndent();
	emitAssignment(stmt->getLhs(), stmt->getRhs());
	out << ";\n";
}

/**
* @brief Emits the given assignment (without leading or trailing whitespace).
*/
void CHLLWriter::emitAssignment(ShPtr<Expression> lhs, ShPtr<Expression> rhs) {
	CompoundOpManager::CompoundOp compoundOp(
		compoundOpManager->tryOptimizeToCompoundOp(lhs, rhs));
	lhs->accept(this);
	if (compoundOp.isUnaryOperator()) {
		// ++ or --
		out << compoundOp.getOperator();
	} else {
		// = or X=, where X is an operator
		out << " " << compoundOp.getOperator() << " ";

		emitConstantsInStructuredWay = true;
		compoundOp.getOperand()->accept(this);
		emitConstantsInStructuredWay = false;
	}
}

/**
* @brief Emits the definition of the initialization variable of the given loop
*        when it is needed.
*/
void CHLLWriter::emitInitVarDefWhenNeeded(ShPtr<UForLoopStmt> loop) {
	// When the initialization part of the loop is a definition, we want to
	// emit, e.g.,
	//
	//     for (int i = 1; ...
	//
	// instead of just
	//
	//     for (i = 1; ...

	if (!loop->isInitDefinition()) {
		return;
	}

	auto assign = cast<AssignOpExpr>(loop->getInit());
	if (!assign) {
		return;
	}

	auto lhsVar = cast<Variable>(assign->getFirstOperand());
	if (!lhsVar) {
		return;
	}

	lhsVar->getType()->accept(this);
	out << " ";
}

// Only here is variables type emitted.
void CHLLWriter::visit(ShPtr<VarDefStmt> stmt) {
	out << getCurrentIndent();
	emitVarWithType(stmt->getVar());

	// Initializer.
	if (ShPtr<Expression> init = stmt->getInitializer()) {
		out << " = ";

		emitConstantsInStructuredWay = true;
		if (ShPtr<ConstStruct> constStruct = cast<ConstStruct>(init)) {
			// When defining a structure, we do not need to emit a cast.
			emitConstStruct(constStruct, false);
		} else {
			init->accept(this);
		}
		emitConstantsInStructuredWay = false;
	}

	out << ";";

	tryEmitVarInfoInComment(stmt->getVar());

	out << "\n";
}

void CHLLWriter::visit(ShPtr<CallStmt> stmt) {
	out << getCurrentIndent();
	stmt->getCall()->accept(this);
	out << ";\n";
}

void CHLLWriter::visit(ShPtr<ReturnStmt> stmt) {
	out << getCurrentIndent() << "return";
	if (ShPtr<Expression> retVal = stmt->getRetVal()) {
		out << " ";
		retVal->accept(this);
	}
	out << ";\n";
}

void CHLLWriter::visit(ShPtr<EmptyStmt> stmt) {
	// Nothing to be emitted.
}

void CHLLWriter::visit(ShPtr<IfStmt> stmt) {
	// Emit the first if clause and other else-if clauses (if any).
	for (auto i = stmt->clause_begin(), e = stmt->clause_end(); i != e; ++i) {
		out << getCurrentIndent();
		out << (i == stmt->clause_begin() ? "if " : " else if ");
		out << "(";
		i->first->accept(this);
		out << ") ";
		emitBlock(i->second);
	}

	// Emit the else clause (if any).
	if (stmt->hasElseClause()) {
		out << " else ";
		emitBlock(stmt->getElseClause());
	}

	out << "\n";
}

void CHLLWriter::visit(ShPtr<SwitchStmt> stmt) {
	out << getCurrentIndent();
	out << "switch (";
	stmt->getControlExpr()->accept(this);
	out << ") {\n";
	increaseIndentLevel();
	// For all cases...
	for (auto i = stmt->clause_begin(), e = stmt->clause_end(); i != e; ++i) {
		out << getCurrentIndent();
		if (i->first) {
			out << "case ";
			i->first->accept(this);
			out << ":";
		} else {
			out << "default:";
		}
		out << " ";

		emitBlock(i->second);
		out << "\n";
	}
	decreaseIndentLevel();
	out << getCurrentIndent() << "}\n";
}

void CHLLWriter::visit(ShPtr<WhileLoopStmt> stmt) {
	out << getCurrentIndent() << "while (";
	stmt->getCondition()->accept(this);
	out << ") ";
	emitBlock(stmt->getBody());
	out << "\n";
}

void CHLLWriter::visit(ShPtr<ForLoopStmt> stmt) {
	out << getCurrentIndent() << "for (";
	stmt->getIndVar()->getType()->accept(this);
	out << " ";
	stmt->getIndVar()->accept(this);
	out << " = ";
	stmt->getStartValue()->accept(this);
	out << "; ";
	stmt->getEndCond()->accept(this);
	out << "; ";
	// Try to emit as readable step as possible.
	if (ShPtr<ConstInt> stepInt = cast<ConstInt>(stmt->getStep())) {
		if (stepInt->getValue() == 1) {
			// i++
			stmt->getIndVar()->accept(this);
			out << "++";
		// `stepInt->getValue() == -1` does not work.
		} else if (-stepInt->getValue() == 1) {
			// i--
			stmt->getIndVar()->accept(this);
			out << "--";
		} else if (stepInt->isNegative()) {
			// i -= x
			stmt->getIndVar()->accept(this);
			out << " -= ";
			ShPtr<ConstInt> negStepInt(ConstInt::create(-stepInt->getValue()));
			negStepInt->accept(this);
		} else {
			// i += x
			stmt->getIndVar()->accept(this);
			out << " += ";
			stmt->getStep()->accept(this);
		}
	} else {
		// i += x (generic)
		stmt->getIndVar()->accept(this);
		out << " += ";
		stmt->getStep()->accept(this);
	}
	out << ") ";
	emitBlock(stmt->getBody());
	out << "\n";
}

void CHLLWriter::visit(ShPtr<UForLoopStmt> stmt) {
	out << getCurrentIndent() << "for (";
	if (auto init = stmt->getInit()) {
		emitInitVarDefWhenNeeded(stmt);
		init->accept(this);
	}
	out << ";";
	if (auto cond = stmt->getCond()) {
		out << " ";
		cond->accept(this);
	}
	out << ";";
	if (auto step = stmt->getStep()) {
		out << " ";
		step->accept(this);
	}
	out << ") ";
	emitBlock(stmt->getBody());
	out << "\n";
}

void CHLLWriter::visit(ShPtr<BreakStmt> stmt) {
	out << getCurrentIndent() << "break;\n";
}

void CHLLWriter::visit(ShPtr<ContinueStmt> stmt) {
	out << getCurrentIndent() << "continue;\n";
}

void CHLLWriter::visit(ShPtr<GotoStmt> stmt) {
	out << getCurrentIndent() << "goto " << getGotoLabel(stmt->getTarget())
		<< ";\n";
}

void CHLLWriter::visit(ShPtr<UnreachableStmt> stmt) {
	out << getCurrentIndent() << comment("UNREACHABLE") << "\n";
}

void CHLLWriter::visit(ShPtr<FloatType> type) {
	out << "float";
	out << type->getSize();
	out << "_t";
}

void CHLLWriter::visit(ShPtr<IntType> type) {
	if (type->isBool()) {
		out << "bool";
		return;
	}

	// Emit 8-bit integers as chars, not as int8_t/uint8_t, because char is
	// more readable.
	if (type->getSize() == 8) {
		if (type->isUnsigned()) {
			out << "unsigned ";
		}
		out << "char";
		return;
	}

	if (type->isUnsigned()) {
		out << "u";
	}
	out << "int" << type->getSize() << "_t";
}

void CHLLWriter::visit(ShPtr<PointerType> type) {
	// Pointers to functions have to emitted in a special way because of C
	// syntax.
	if (isPointerToFunc(type)) {
		emitPointerToFunc(type);
		return;
	}

	// Pointers to arrays have to emitted in a special way because of C
	// syntax.
	if (isPointerToArray(type)) {
		emitPointerToArray(type);
		return;
	}

	int numOfStars = 1; // It is a pointer, min one "*".
	// Compute the number of '*'s before the pointed-to value.
	ShPtr<PointerType> pointedType(type);
	while (cast<PointerType>(pointedType->getContainedType())) {
		pointedType = cast<PointerType>(pointedType->getContainedType());
		numOfStars++;
	}
	// If type is a pointer get the contained type.
	pointedType->getContainedType()->accept(this);
	// If type is followed by "*"s, emit a space.
	if (numOfStars > 0) {
		out << " ";
	}
	// Emit "*"s.
	for (int star = 0; star < numOfStars; ++star) {
		out << "*";
	}
}

void CHLLWriter::visit(ShPtr<StringType> type) {
}

void CHLLWriter::visit(ShPtr<ArrayType> type) {
	emitTypeOfElementsInArray(type);
}

void CHLLWriter::visit(ShPtr<StructType> type) {
	// Named structures can be emitted by using their name, unnamed structures
	// are emitted inline including their full type.
	auto i = structNames.find(type);
	if (i != structNames.end()) {
		// It has a name -> use it.
		out << "struct " << i->second;
	} else {
		// Emit the structure inline.
		emitStructDeclaration(type, true);
	}
}

void CHLLWriter::visit(ShPtr<FunctionType> type) {
	// Due to C syntax, function type has to be handled outside of this visit.
	// The reason is that in C, only a pointer to a function is correct, and a
	// pointer to a function has code before '*' and after '*'. This is why we
	// cannot emit a function type in here.
	FAIL("FunctionType should be handled outside of visit(ShPtr<FunctionType>)");
}

void CHLLWriter::visit(ShPtr<VoidType> type) {
	out << "void";
}

void CHLLWriter::visit(ShPtr<UnknownType> type) {
	out << "unknown";
}

/**
* @brief Returns @c true if we should emit the <em>Function Prototypes</em>
*        header, @c false otherwise.
*/
bool CHLLWriter::shouldEmitFunctionPrototypesHeader() const {
	if (module->hasMainFunc()) {
		return module->getNumOfFuncDefinitions() > 1;
	}
	return module->hasFuncDefinitions();
}

/**
* @brief Emits prototypes of the given functions.
*
* @return @c true if some code has been emitted, @c false otherwise.
*/
bool CHLLWriter::emitFunctionPrototypes(const FuncSet &funcs) {
	FuncVector toEmit(funcs.begin(), funcs.end());
	sortByName(toEmit);
	bool somethingEmitted = false;
	for (auto &func : toEmit) {
		somethingEmitted |= emitFunctionPrototype(func);
	}
	return somethingEmitted;
}

/**
* @brief Emits standard function prototypes.
*
* @return @c true if some code was emitted, @c false otherwise.
*/
bool CHLLWriter::emitStandardFunctionPrototypes() {
	// We want to emit prototypes for the following functions:
	//
	//   - All functions with bodies.
	//   - All functions marked as "user-defined".
	//
	// Notes:
	//
	//   - We cannot consider just user-defined functions because there may be
	//     no config file from which this information is taken (in such case, we
	//     would emit no function prototypes at all).
	FuncSet funcsToEmit(
		module->func_definition_begin(),
		module->func_definition_end()
	);
	addToSet(module->getUserDefinedFuncs(), funcsToEmit);
	return emitFunctionPrototypes(funcsToEmit);
}

/**
* @brief Emits prototypes for functions which do not have any associated header
*        file.
*
* @return @c true if some code has been emitted, @c false otherwise.
*/
bool CHLLWriter::emitFunctionPrototypesForNonLibraryFuncs() {
	bool somethingEmitted = false;

	for (auto i = module->func_declaration_begin(),
			e = module->func_declaration_end(); i != e; ++i) {
		if (HeadersForDeclaredFuncs::hasAssocHeader(module, *i)) {
			continue;
		}

		if (!somethingEmitted) {
			out << comment("The following linked functions do not have "
				"any associated header file:\n");
		}
		emitFunctionPrototype(*i);
		somethingEmitted = true;
	}

	return somethingEmitted;
}

/**
* @brief Emits a prototype of the given function, including the ending newline.
*
* @param[in] func Function whose prototype is to be emitted.
*
* @return @c true if some code has been emitted, @c false otherwise.
*
* @par Preconditions
*  - @a func is non-null
*/
bool CHLLWriter::emitFunctionPrototype(ShPtr<Function> func) {
	// Emit a prototype for the main function only if it is referenced
	// indirectly somewhere in the module (see the description of
	// IndirectFuncRefAnalysis for more details). Otherwise, its prototype is
	// not needed.
	if (module->isMainFunc(func) &&
			!IndirectFuncRefAnalysis::isIndirectlyReferenced(module, func)) {
		return false;
	}

	emitFunctionHeader(func);
	out << ";\n";
	return true;
}

/**
* @brief Emits the given function definition.
*
* @par Preconditions
*  - @a func is a function efinition
*/
void CHLLWriter::emitFunctionDefinition(ShPtr<Function> func) {
	PRECONDITION(func->isDefinition(), "it has to be a definition");

	emitFunctionHeader(func);
	out << " ";
	emitBlock(func->getBody());
	out << "\n";
}

/**
* @brief Emits the header of the given function.
*
* Consider the following two functions:
* @code
* void func1(int a, int b);
* float func2(float a) { return a + 1; }
* @endcode
* For @c func1(), it emits
* @code
* void func1(int a, int b)
* @endcode
* and for @c func2(), it emits
* @code
* float func2(float a)
* @endcode
*
* A newline is NOT emitted.
*/
void CHLLWriter::emitFunctionHeader(ShPtr<Function> func) {
	ShPtr<Type> retType(func->getRetType());

	// C has a special syntax for functions returning a pointer to a function.
	if (isPointerToFunc(retType)) {
		emitHeaderOfFuncReturningPointerToFunc(func);
		return;
	}

	// C has a special syntax for functions returning a pointer to an array.
	if (isPointerToArray(retType)) {
		emitHeaderOfFuncReturningPointerToArray(func);
		return;
	}

	if (module->isMainFunc(func)) {
		// The main function. We have to use the classic C data types to
		// prevent C syntax checker from complaining about the use of
		// unexpected types. For example, the return type of main() is assumed
		// to be int, not int32_t.
		out << "int " << func->getName() << "(";
		const VarVector &params(func->getParams());
		if (params.size() == 2) {
			auto paramIter = params.begin();
			out << "int " << (*paramIter++)->getName();
			out << ", char ** " << (*paramIter++)->getName();
		}
		out << ")";
		return;
	}

	// Ordinary function.
	retType->accept(this);
	out << " " << func->getName() << "(";
	emitFunctionParameters(func);
	out << ")";
}

/**
* @brief A specialization of emitFunctionHeader() for functions returning a
*        pointer to a function.
*
* @see emitFunctionHeader()
*/
void CHLLWriter::emitHeaderOfFuncReturningPointerToFunc(ShPtr<Function> func) {
	// Instead of
	//
	//     void (*)(int, int) func(int a)
	//
	// we have to emit
	//
	//     void (*func(int a))(int, int)
	//
	// because of the special syntax of C for functions returning a pointer to
	// a function.
	ShPtr<Type> retType(func->getRetType());
	ShPtr<FunctionType> retFuncType(getFuncTypeFromPointerToFunc(retType));

	emitReturnType(retFuncType);
	out << " (";
	emitStarsBeforePointedValue(cast<PointerType>(retType));
	out << func->getName();
	out << "(";
	emitFunctionParameters(func);
	out << "))(";
	emitFunctionParameters(retFuncType);
	out << ")";
}

/**
* @brief A specialization of emitFunctionHeader() for functions returning a
*        pointer to an array.
*
* @see emitFunctionHeader()
*/
void CHLLWriter::emitHeaderOfFuncReturningPointerToArray(ShPtr<Function> func) {
	// Instead of
	//
	//     int (*)[10] func(int a)
	//
	// we have to emit
	//
	//     int (*func(int a))[10]
	//
	// because of the special syntax of C for functions returning a pointer to
	// an array.
	ShPtr<Type> retType(func->getRetType());
	ShPtr<ArrayType> retArrayType(getArrayTypeFromPointerToArray(retType));

	emitTypeOfElementsInArray(retArrayType);
	out << " (";
	emitStarsBeforePointedValue(cast<PointerType>(retType));
	out << func->getName();
	out << "(";
	emitFunctionParameters(func);
	out << "))";
	emitArrayDimensions(retArrayType);
}

/**
* @brief Emits the parameters of the given function.
*
* For example, if the function is
* @code
* void func(int a, char *p, ...);
* @endcode
* this function emits
* @code
* int a, char *p, ...
* @endcode
*/
void CHLLWriter::emitFunctionParameters(ShPtr<Function> func) {
	// For each parameter...
	bool paramEmitted = false;
	for (const auto &param : func->getParams()) {
		if (paramEmitted) {
			out << ", ";
		}
		emitVarWithType(param);
		paramEmitted = true;
	}

	// Optional vararg indication.
	if (func->isVarArg()) {
		if (paramEmitted) {
			out << ", ";
		}
		out << "...";
		paramEmitted = true;
	}

	if (!paramEmitted) {
		out << "void";
	}
}

/**
* @brief Emits the given variable alongside with its type.
*
* For example, if @a var is named @c foo and is of type @c int, the following
* code is emitted:
* @code
* int foo
* @endcode
*
* @par Preconditions
*  - @a var is non-null
*/
void CHLLWriter::emitVarWithType(ShPtr<Variable> var) {
	PRECONDITION_NON_NULL(var);

	ShPtr<Type> varType(var->getType());

	// Pointers to functions have to emitted in a special way because of C
	// syntax.
	if (isPointerToFunc(varType)) {
		emitPointerToFunc(ucast<PointerType>(varType), var);
		return;
	}

	// Arrays of function pointers have to be emitted in a special way because
	// of C syntax.
	if (isArrayOfFuncPointers(varType)) {
		emitArrayOfFuncPointers(ucast<ArrayType>(varType), var);
		return;
	}

	// Pointers to arrays have to emitted in a special way because of C
	// syntax.
	if (isPointerToArray(varType)) {
		emitPointerToArray(ucast<PointerType>(varType), var);
		return;
	}

	varType->accept(this);
	out << " ";
	var->accept(this);

	// For an array, emit its dimensions.
	if (ShPtr<ArrayType> arrayType = cast<ArrayType>(varType)) {
		emitArrayDimensions(arrayType);
	}
}

/**
* @brief Emits a pointer to the given function, possibly with the given
*        variable.
*
* Let us assume that @a funcType is a pointer to a void function, which has a
* single parameter of type @c int. Then, if we do not pass @a var, the
* following code is emitted:
* @code
* void (*)(int)
* @endcode
* However, if @a var is non-null and its name is @c foo, then the following
* code is emitted:
* @code
* void (*foo)(int)
* @endcode
*
* @par Preconditions
*  - @a pointerToFuncType is a pointer to a function
*/
void CHLLWriter::emitPointerToFunc(ShPtr<PointerType> pointerToFuncType,
		ShPtr<Variable> var) {
	ShPtr<FunctionType> funcType(getFuncTypeFromPointerToFunc(pointerToFuncType));
	PRECONDITION(funcType,
		"pointerToFuncType is expected to be a pointer to a function");

	emitReturnType(funcType);
	out << " (";
	emitStarsBeforePointedValue(pointerToFuncType);
	emitNameOfVarIfExists(var);
	out << ")(";
	emitFunctionParameters(funcType);
	out << ")";
}

/**
* @brief Emits the given array of function pointers, possibly with the given
* variable.
*
* Let us assume that @a arrayType is a three-item array of pointers to
* functions that have a single parameter of type @c int. Then, if we do not
* pass @a var, the following code is emitted:
* @code
* void (*[3])(int)
* @endcode
* However, if @a var is non-null and its name is @c foo, then the following
* code is emitted:
* @code
* void (*foo[3])(int)
* @endcode
*
* @par Preconditions
*  - @a arrayType is an array of function pointers
*/
void CHLLWriter::emitArrayOfFuncPointers(ShPtr<ArrayType> arrayType,
		ShPtr<Variable> var) {
	PRECONDITION(isArrayOfFuncPointers(arrayType),
		"arrayType is expected to be an array of function pointers");

	ShPtr<PointerType> ptrToFuncType(ucast<PointerType>(
		arrayType->getContainedType()));
	ShPtr<FunctionType> funcType(getFuncTypeFromPointerToFunc(ptrToFuncType));

	emitReturnType(funcType);
	out << " (";
	emitStarsBeforePointedValue(ptrToFuncType);
	emitNameOfVarIfExists(var);
	emitArrayDimensions(arrayType);
	out << ")(";
	emitFunctionParameters(funcType);
	out << ")";
}

/**
* @brief Emits a pointer to the given array, possibly with the given variable.
*
* Let us assume that @a arrayType is a pointer to an array of 10 ints. Then, if
* we do not pass @a var, the following code is emitted:
* @code
* int (*)[10]
* @endcode
* However, if @a var is non-null and its name is @c foo, then the following
* code is emitted:
* @code
* int (*foo)[10]
* @endcode
*
* @par Preconditions
*  - @a pointerToArrayType is a pointer to an array
*/
void CHLLWriter::emitPointerToArray(ShPtr<PointerType> pointerToArrayType,
		ShPtr<Variable> var) {
	ShPtr<ArrayType> arrayType(getArrayTypeFromPointerToArray(pointerToArrayType));
	PRECONDITION(arrayType,
		"pointerToArrayType is expected to be a pointer to an array");

	emitTypeOfElementsInArray(arrayType);
	out << " (";
	emitStarsBeforePointedValue(pointerToArrayType);
	emitNameOfVarIfExists(var);
	out << ")";
	emitArrayDimensions(arrayType);
}

/**
* @brief Emits the dimensions of the given array.
*/
void CHLLWriter::emitArrayDimensions(ShPtr<ArrayType> arrayType) {
	for (const auto &dim : arrayType->getDimensions()) {
		emitArrayDimension(dim);
	}
}

/**
* @brief Emits the given array dimension.
*/
void CHLLWriter::emitArrayDimension(std::size_t dimension) {
	out << "[" << dimension << "]";
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
void CHLLWriter::emitInitializedConstArray(ShPtr<ConstArray> array) {
	if (shouldBeEmittedInStructuredWay(array)) {
		emitInitializedConstArrayInStructuredWay(array);
	} else {
		emitInitializedConstArrayInline(array);
	}
}

/**
* @brief Emits the given array inline.
*/
void CHLLWriter::emitInitializedConstArrayInline(ShPtr<ConstArray> array) {
	// We emit the array in the following way (just an example):
	//
	//     char *arr[3] = {"string1", "string2", "string3"}
	//
	out << "{";
	emitSequenceWithAccept(array->getInitializedValue(), ", ");
	out << "}";
}

/**
* @brief Emits the given array in a structured way (may span over multiple
*        lines).
*/
void CHLLWriter::emitInitializedConstArrayInStructuredWay(ShPtr<ConstArray> array) {
	// We emit the array in the following way (just an example):
	//
	//     char *arr[3] = {
	//         "string1",
	//         "string2",
	//         "string3"
	//     }
	//
	out << "{\n";
	increaseIndentLevel();
	out << getCurrentIndent();
	emitSequenceWithAccept(array->getInitializedValue(),
		",\n" + getCurrentIndent());
	decreaseIndentLevel();
	out << getCurrentIndent();
	out << "\n}";
}

/**
* @brief Emits the given uninitialized array.
*
* @par Preconditions
*  - @a array is non-null and uninitialized
*/
void CHLLWriter::emitUninitializedConstArray(ShPtr<ConstArray> array) {
	// We cannot emit just '{}' because ISO C99 forbids empty initializer
	// braces. Therefore, we have to initialize the array to zeros. There is
	// nothing else to do than initializing the array to some values, and zero
	// is just as good value as any other.
	out << "{0}";
}

/**
* @brief Emits the type of elements in the given array.
*/
void CHLLWriter::emitTypeOfElementsInArray(ShPtr<ArrayType> arrayType) {
	arrayType->getContainedType()->accept(this);
}

/**
* @brief Emits the given cast in the standard way.
*/
void CHLLWriter::emitCastInStandardWay(ShPtr<CastExpr> expr) {
	out << "(";
	expr->getType()->accept(this);
	out << ")";
	expr->getOperand()->accept(this);
}

/**
* @brief Emits @c '*'s before the pointed value (there can be more than one).
*/
void CHLLWriter::emitStarsBeforePointedValue(ShPtr<PointerType> ptrType) {
	do {
		out << "*";
	} while ((ptrType = cast<PointerType>(ptrType->getContainedType())));
}

/**
* @brief Emits parameters of the given function.
*/
void CHLLWriter::emitFunctionParameters(ShPtr<FunctionType> funcType) {
	for (auto i = funcType->param_begin(), e = funcType->param_end();
			i != e; ++i) {
		if (i != funcType->param_begin()) {
			out << ", ";
		}
		(*i)->accept(this);
	}
}

/**
* @brief Emits the return type of the given function.
*/
void CHLLWriter::emitReturnType(ShPtr<FunctionType> funcType) {
	funcType->getRetType()->accept(this);
}

/**
* @brief Emits the name of @a var if it is a non-null pointer.
*/
void CHLLWriter::emitNameOfVarIfExists(ShPtr<Variable> var) {
	if (var) {
		var->accept(this);
	}
}

/**
* @brief Emits the given structure literal.
*
* @param[in] constant Structure literal to be emitted.
* @param[in] emitCast Emit a cast before the literal?
*
* If @a emitCast is @c true, this function emits a cast of the form
* <tt>(structure X)</tt> before the literal, where @c X is the name of the
* structure. This is needed if the literal is used outside of the right-hand
* side of VarDefStmt.
*
* When the @c emittingGlobalVarDefs data member is set to @c true, this
* function does not emit any casts, even if @a emitCast is @c true. The reason
* is that on the global level, casts of structures are considered non-constant.
* For example, if we emit
* @code
* struct struct4 t = {.e0 = (struct struct3){.e0 = 0}};
* @endcode
* we get the following warning:
* @code
* error: initializer element is not constant
* @endcode
* Instead, we have to emit just
* @code
* struct struct4 t = {.e0 = {.e0 = 0}};
* @endcode
* i.e. drop the cast.
*
* When the @c emitConstantsInStructuredWay data member is set to @c true, the
* constant may be emitted in a structured way, i.e. spanning over multiple
* lines. Whether it is actually emitted in this way depends on the result of
* shouldBeEmittedInStructuredWay().
*/
void CHLLWriter::emitConstStruct(ShPtr<ConstStruct> constant, bool emitCast) {
	if (emitCast && !emittingGlobalVarDefs) {
		out << "(";
		constant->getType()->accept(this);
		out << ")";
	}

	bool emitInStructuredWay = shouldBeEmittedInStructuredWay(constant);

	out << "{";
	if (emitInStructuredWay) {
		out << "\n";
		increaseIndentLevel();
		out << getCurrentIndent();
	}

	bool someInitEmitted = false;
	// Do not emit an initializer for fields that are initialized by an
	// uninitialized array because there is no way of emitting such an
	// initializer (see emitUninitializedConstArray()). However, if there are
	// no other initializers in the structure, we have to emit at least one of
	// them because {} is not a valid structure initialization. When such a
	// situation happens, we emit all the initializers, even those of
	// uninitialized arrays.
	bool forceEmissionOfAllInits = hasOnlyUninitializedConstArrayInits(constant);
	ConstStruct::Type value(constant->getValue());
	for (const auto &member : value) {
		// If there is at least one initializer differing from an uninitialized
		// ConstArray, we may skip the initializers of uninitialized arrays
		// (see the comment before the loop).
		if (isUninitializedConstArray(member.second) && !forceEmissionOfAllInits) {
			continue;
		}

		if (someInitEmitted) {
			if (emitInStructuredWay) {
				out << ",\n" << getCurrentIndent();
			} else {
				out << ", ";
			}
		}

		out << ".e";
		member.first->accept(this);
		out << " = ";
		member.second->accept(this);
		someInitEmitted = true;
	}

	if (emitInStructuredWay) {
		out << "\n";
		decreaseIndentLevel();
		out << getCurrentIndent();
	}
	out << "}";
}

/**
* @brief Emits a declaration of the given structure.
*
* @param[in] structType Type of the structure whose declaration is to be
*                       emitted.
* @param[in] emitInline If @c true, the type is emitted without any newlines.
*
* Example: When @c emitInline is @c false, it emits
* @code
* struct Name {
*    type1 name1;
*    type2 name2;
*    ...
* }
* @endcode
* without a trailing newline. When @c emitInline is @c true, it emits
* @code
* struct Name { type1 name1; type2 name2; ... }
* @endcode
* Again, there is no trailing newline.
*/
void CHLLWriter::emitStructDeclaration(ShPtr<StructType> structType,
		bool emitInline) {
	if (!emitInline) {
		out << getCurrentIndent();
	}
	out << "struct ";

	// Emit the name of the structure only if it has one.
	auto i = structNames.find(structType);
	if (i != structNames.end()) {
		out << i->second << " ";
	}

	out << "{";
	if (!emitInline) {
		out << "\n";
		increaseIndentLevel();
	}
	// For each element...
	const StructType::ElementTypes &elements = structType->getElementTypes();
	for (StructType::ElementTypes::size_type i = 0; i < elements.size(); ++i) {
		if (!emitInline) {
			out << getCurrentIndent();
		}
		ShPtr<Type> elemType(elements.at(i));
		// Create a dummy variable so we can use emitVarWithType().
		// All elements are named e#, where # is a number.
		emitVarWithType(Variable::create("e" + toString(i), elemType));
		out << ";";
		if (!emitInline) {
			out << "\n";
		} else if (i != elements.size() - 1) {
			// Separate the fields with a space when emitting inline.
			out << " ";
		}
	}
	if (!emitInline) {
		decreaseIndentLevel();
	}
	out << "}";
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
void CHLLWriter::emitBlock(ShPtr<Statement> stmt) {
	out << "{\n";
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
	out << getCurrentIndent() << "}";
}

/**
* @brief Emits a label of @a stmt if it is needed.
*
* A label is needed if @a stmt is the target of a goto statement.
*/
void CHLLWriter::emitGotoLabelIfNeeded(ShPtr<Statement> stmt) {
	if (stmt->isGotoTarget()) {
		out << getIndentForGotoLabel() << getGotoLabel(stmt) << ":";

		if (isa<VarDefStmt>(skipEmptyStmts(stmt))) {
			// ISO C99 requires that a label can only be a part of a statement,
			// and a variable definition/declaration is not considered to be a
			// statement. To this end, we put the empty statement (';') after
			// the colon to make the code syntactically correct.
			out << ";";
		}

		if (isa<EmptyStmt>(stmt) && !skipEmptyStmts(stmt)) {
			// ISO C99 forbids labels at the end of compound statements, i.e.
			// labels which are not followed by any statement. To this end, in
			// such situations, we put the empty statement (';') after the
			// colon to make the code syntactically correct.
			out << ";";
		}

		out << "\n";
	}
}

/**
* @brief Emits a suffix for the given floating-point constant (if needed).
*/
void CHLLWriter::emitConstFloatSuffixIfNeeded(ShPtr<ConstFloat> constant) {
	auto size = constant->getSize();
	if (size <= 32) {
		out << "f"; // float
	} else if (size <= 64) {
		// double literals do not have any suffix.
	} else {
		out << "L"; // long double (the biggest type we have)
	}
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
void CHLLWriter::emitDebugComment(std::string comment, bool indent) {
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
* @brief Generates a new name for an unnamed structure.
*
* @param[in] usedStructTypes All used structured types.
*
* The @a usedStructTypes parameter is needed because all the created names have
* to differ from all the existing names of structures.
*/
std::string CHLLWriter::genNameForUnnamedStruct(const StructTypeVector &usedStructTypes) {
	std::string structName;
	// Create new names until we find a name without a clash.
	do {
		structName = "struct" + toString(++unnamedStructCounter);
		for (const auto &type : usedStructTypes) {
			if (cast<StructType>(type)->getName() == structName) {
				// We have found a clash, so try a different name.
				structName.clear();
				break;
			}
		}
	} while (structName.empty());
	return structName;
}

} // namespace llvmir2hll
} // namespace retdec
