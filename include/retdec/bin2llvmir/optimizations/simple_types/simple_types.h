/**
* @file include/retdec/bin2llvmir/optimizations/simple_types/simple_types.h
* @brief Simple type reconstruction analysis.
* @copyright (c) 2017 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_SIMPLE_TYPES_SIMPLE_TYPES_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_SIMPLE_TYPES_SIMPLE_TYPES_H

#include <functional>
#include <list>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>

#include <llvm/IR/Function.h>
#include <llvm/IR/Module.h>
#include <llvm/Pass.h>

#include "retdec/bin2llvmir/providers/fileimage.h"
#include "retdec/bin2llvmir/utils/debug.h"

namespace retdec {
namespace bin2llvmir {

class ValueEntry;
class TypeEntry;
class EquationEntry;
class EqSet;
class EqSetContainer;

/**
 * Priority of data type sources.
 * Higher values have higher priority.
 */
enum class eSourcePriority
{
	PRIORITY_NONE = 0,
	PRIORITY_LTI,
	PRIORITY_DEBUG
};

/**
 * Entry representing one value in @c EqSet.
 */
class ValueEntry
{
	public:
		ValueEntry(llvm::Value* v = nullptr, eSourcePriority p = eSourcePriority::PRIORITY_NONE);
		llvm::Type* getTypeForPropagation() const;
		bool operator==(const ValueEntry& o) const;
		bool operator<(const ValueEntry& o) const;
		std::size_t hash() const;
		friend std::ostream& operator<<(std::ostream& out, const ValueEntry& ve);

	public:
		llvm::Value* value = nullptr;
		eSourcePriority priority = eSourcePriority::PRIORITY_NONE;
};
struct ValueEntryHash
{
	std::size_t operator() (const ValueEntry& v) const { return v.hash(); }
};

/**
 * Entry representing one data type in @c EqSet.
 */
class TypeEntry
{
	public:
		TypeEntry(llvm::Type* t = nullptr, eSourcePriority p = eSourcePriority::PRIORITY_NONE);
		bool operator==(const TypeEntry& o) const;
		bool operator<(const TypeEntry& o) const;
		std::size_t hash() const;
		friend std::ostream& operator<<(std::ostream& out, const TypeEntry& te);

	public:
		llvm::Type* type = nullptr;
		eSourcePriority priority = eSourcePriority::PRIORITY_NONE;
};
struct TypeEntryHash
{
	std::size_t operator() (const TypeEntry& t) const { return t.hash(); }
};

/**
 * Entry representing equation (relation) between two equivalence sets.
 */
class EquationEntry
{
	public:
		static EquationEntry otherIsPtrToThis(EqSet* o);
		static EquationEntry thisIsPtrToOther(EqSet* o);

		bool operator==(const EquationEntry& o) const;
		bool operator<(const EquationEntry& o) const;
		std::size_t hash() const;
		friend std::ostream& operator<<(std::ostream& out, const EquationEntry& ee);

		bool isOtherIsPtrToThis();
		bool isThisIsPtrToOther();

	public:
		EqSet* other;

	private:
		enum class eqType
		{
			otherIsPtrToThis,
			thisIsPtrToOther
		};

	private:
		EquationEntry(EqSet* o, eqType t);

	private:
		eqType type;
};
struct EquationEntryHash
{
	std::size_t operator() (const EquationEntry& e) const { return e.hash(); }
};

using ValueEntrySet = std::unordered_set<ValueEntry, ValueEntryHash>;
using TypeEntrySet = std::unordered_set<TypeEntry, TypeEntryHash>;
using EquationEntrySet = std::unordered_set<EquationEntry, EquationEntryHash>;

/**
 * Equivalence set -- object in set have to same type.
 */
class EqSet
{
	public:
		EqSet();
		void insert(Config* config, llvm::Value* v, eSourcePriority p = eSourcePriority::PRIORITY_NONE);
		void insert(llvm::Type* t, eSourcePriority p = eSourcePriority::PRIORITY_NONE);
		void propagate(llvm::Module* module);
		void apply(
				llvm::Module* module,
				Config* config,
				FileImage* objf,
				std::unordered_set<llvm::Instruction*>& instToErase);

		friend std::ostream& operator<<(std::ostream& out, const EqSet& eq);

	private:
		llvm::Type* getHigherPriorityType(
				llvm::Module* module,
				llvm::Type* t1,
				llvm::Type* t2);
		llvm::Type* getHigherPriorityTypePrivate(
				llvm::Module* module,
				llvm::Type* t1,
				llvm::Type* t2,
				std::unordered_set<llvm::Type*>& seen);

	public:
		/// Each instance gets its own unique ID for debug print purposes.
		static unsigned newUID;
		const unsigned id;

		/// Type of an entire equivalence set.
		TypeEntry masterType;
		/// Values in the set.
		ValueEntrySet valSet;
		/// This allows to add certain types to set without having a value for them.
		TypeEntrySet typeSet;
		/// This allows to propagate type to another equivalence set, which may not
		/// have the same type as this set. E.g. this=pointer(other).
		EquationEntrySet equationSet;
};

/**
 * Equivalence sets container.
 */
class EqSetContainer
{
	public:
		EqSet& createEmptySet();
		void propagate(llvm::Module* module);
		void apply(
				llvm::Module* module,
				Config* config,
				FileImage* objf,
				std::unordered_set<llvm::Instruction*>& valsToErase);

		friend std::ostream& operator<<(std::ostream& out, const EqSetContainer& eqs);

	public:
		std::list<EqSet> eqSets;
};

using ValueMap = std::unordered_map<llvm::Value*, EqSet*>;
using ValuePair = std::pair<llvm::Value*, llvm::Value*>;
using ValuePairList = std::list<ValuePair>;

/**
 * Simple data type analysis.
 */
class SimpleTypesAnalysis : public llvm::ModulePass
{
	public:
		static char ID;
		SimpleTypesAnalysis();

		virtual bool runOnModule(llvm::Module& m) override;
		virtual void getAnalysisUsage(llvm::AnalysisUsage& AU) const override;

	private:
		void buildEqSets(llvm::Module& M);
		void buildEquations();
		void processRoot(llvm::Value* root);
		void processValue(std::queue<llvm::Value*>& toProcess, EqSet& eqSet);
		void processUse(llvm::Value* c, llvm::Value* x, std::queue<llvm::Value*>& toProcess, EqSet& eqSet);
		void eraseObsoleteInstructions();
		void setGlobalConstants();

	private:
		ValueMap processedObjs;
		EqSetContainer eqSets;
		ValuePairList val2PtrVal;

		ReachingDefinitionsAnalysis RDA;
		llvm::Module* module = nullptr;
		const llvm::GlobalVariable* _specialGlobal = nullptr;
		Config* config = nullptr;
		FileImage* objf = nullptr;

		std::unordered_set<llvm::Instruction*> instToErase;
};

} // namespace bin2llvmir
} // namespace retdec

#endif
