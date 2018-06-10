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

/// Address range.
using AddressRange = std::pair<std::uint64_t, std::uint64_t>;

/// No address range.
extern const AddressRange NO_ADDRESS_RANGE;

/// Line range.
using LineRange = std::pair<std::uint64_t, std::uint64_t>;

/// No line range.
extern const LineRange NO_LINE_RANGE;

/// Set of strings.
using StringSet = std::set<std::string>;

/// Set of values.
using ValueSet = std::set<ShPtr<Value>>;

/// Set of variables.
using VarSet = std::set<ShPtr<Variable>>;

/// Set of VarDefStmt.
using VarDefStmtSet = std::set<ShPtr<VarDefStmt>>;

/// Set of types.
using TypeSet = std::set<ShPtr<Type>>;

/// Set of structured types.
using StructTypeSet = std::set<ShPtr<StructType>>;

/// Set of statements.
using StmtSet = std::set<ShPtr<Statement>>;

/// Set of expressions.
using ExpressionSet = std::set<ShPtr<Expression>>;

/// Set of function calls.
using CallSet = std::set<ShPtr<CallExpr>>;

/// Set of functions.
using FuncSet = std::set<ShPtr<Function>>;

/// Unordered set of statements.
using StmtUSet = std::unordered_set<ShPtr<Statement>>;

/// Unordered set of types.
using TypeUSet = std::unordered_set<ShPtr<Type>>;

/// Vector of strings.
using StringVector = std::vector<std::string>;

/// Vector of values.
using ValueVector = std::vector<ShPtr<Value>>;

/// Vector of variables.
using VarVector = std::vector<ShPtr<Variable>>;

/// Vector of statements.
using StmtVector = std::vector<ShPtr<Statement>>;

/// Vector of expressions.
using ExprVector = std::vector<ShPtr<Expression>>;

/// Vector of function calls.
using CallVector = std::vector<ShPtr<CallExpr>>;

/// Vector of functions.
using FuncVector = std::vector<ShPtr<Function>>;

/// Vector of global variable definitions.
using GlobalVarDefVector = std::vector<ShPtr<GlobalVarDef>>;

/// Vector of structured types.
using StructTypeVector = std::vector<ShPtr<StructType>>;

/// Variable with its initializer.
using VarInitPair = std::pair<ShPtr<Variable>, ShPtr<Expression>>;

/// List of variables with their initializers.
using VarInitPairVector = std::vector<VarInitPair>;

/// Mapping of a string into a string.
using StringStringMap = std::map<std::string, std::string>;

/// Mapping of a string into a type.
using StringTypeMap = std::map<std::string, ShPtr<Type>>;

/// Mapping of a variable into a string.
using VarStringMap = std::map<ShPtr<Variable>, std::string>;

/// Mapping of a string into a variable.
using StringVarMap = std::map<std::string, ShPtr<Variable>>;

/// Mapping of a function into a string.
using FuncStringMap = std::map<ShPtr<Function>, std::string>;

/// Mapping of a 64b int into a string.
using IntStringMap = std::map<std::int64_t, std::string>;

/// Mapping of a variable into a set of variables.
using VarVarSetMap = std::map<ShPtr<Variable>, VarSet>;

/// Unordered mapping of a string into a string.
using StringStringUMap = std::unordered_map<std::string, std::string>;

} // namespace llvmir2hll
} // namespace retdec

#endif
