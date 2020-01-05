/**
* @file include/retdec/llvmir2hll/support/types.h
* @brief Aliases for several useful types.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_LLVMIR2HLL_SUPPORT_TYPES_H
#define RETDEC_LLVMIR2HLL_SUPPORT_TYPES_H

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "retdec/llvmir2hll/support/smart_ptr.h"
#include "retdec/common/address.h"

namespace retdec {
namespace llvmir2hll {

class CallExpr;
class Expression;
class Function;
class GlobalVarDef;
class Statement;
class StructType;
class Type;
class Value;
class VarDefStmt;
class Variable;

/// Address.
using Address = retdec::common::Address;

/// Address range.
using AddressRange = retdec::common::AddressRange;

/// No address range.
extern const AddressRange NO_ADDRESS_RANGE;

/// Line range.
using LineRange = std::pair<std::uint64_t, std::uint64_t>;

/// No line range.
extern const LineRange NO_LINE_RANGE;

/// Set of strings.
using StringSet = std::set<std::string>;

/// Set of values.
using ValueSet = std::set<Value*>;

/// Set of variables.
using VarSet = std::set<Variable*>;

/// Set of VarDefStmt.
using VarDefStmtSet = std::set<VarDefStmt*>;

/// Set of types.
using TypeSet = std::set<Type*>;

/// Set of structured types.
using StructTypeSet = std::set<StructType*>;

/// Set of statements.
using StmtSet = std::set<Statement*>;

/// Set of expressions.
using ExpressionSet = std::set<Expression*>;

/// Set of function calls.
using CallSet = std::set<CallExpr*>;

/// Set of functions.
using FuncSet = std::set<Function*>;

/// Unordered set of statements.
using StmtUSet = std::unordered_set<Statement*>;

/// Unordered set of types.
using TypeUSet = std::unordered_set<Type*>;

/// Vector of strings.
using StringVector = std::vector<std::string>;

/// Vector of values.
using ValueVector = std::vector<Value*>;

/// Vector of variables.
using VarVector = std::vector<Variable*>;

/// Vector of statements.
using StmtVector = std::vector<Statement*>;

/// Vector of expressions.
using ExprVector = std::vector<Expression*>;

/// Vector of function calls.
using CallVector = std::vector<CallExpr*>;

/// Vector of functions.
using FuncVector = std::vector<Function*>;

/// Vector of global variable definitions.
using GlobalVarDefVector = std::vector<GlobalVarDef*>;

/// Vector of structured types.
using StructTypeVector = std::vector<StructType*>;

/// Variable with its initializer.
using VarInitPair = std::pair<Variable*, Expression*>;

/// List of variables with their initializers.
using VarInitPairVector = std::vector<VarInitPair>;

/// Mapping of a string into a string.
using StringStringMap = std::map<std::string, std::string>;

/// Mapping of a string into a type.
using StringTypeMap = std::map<std::string, Type*>;

/// Mapping of a variable into a string.
using VarStringMap = std::map<Variable*, std::string>;

/// Mapping of a string into a variable.
using StringVarMap = std::map<std::string, Variable*>;

/// Mapping of a function into a string.
using FuncStringMap = std::map<Function*, std::string>;

/// Mapping of a 64b int into a string.
using IntStringMap = std::map<std::int64_t, std::string>;

/// Mapping of a variable into a set of variables.
using VarVarSetMap = std::map<Variable*, VarSet>;

/// Unordered mapping of a string into a string.
using StringStringUMap = std::unordered_map<std::string, std::string>;

} // namespace llvmir2hll
} // namespace retdec

#endif
