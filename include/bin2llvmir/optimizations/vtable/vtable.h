/**
 * @file include/bin2llvmir/optimizations/vtable/vtable.h
 * @brief Search for vtables in input file.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#ifndef BIN2LLVMIR_OPTIMIZATIONS_VTABLE_VTABLE_H
#define BIN2LLVMIR_OPTIMIZATIONS_VTABLE_VTABLE_H

#include <map>
#include <vector>

#include <llvm/Pass.h>

#include "tl-cpputils/address.h"
#include "bin2llvmir/optimizations/data_references/data_references.h"
#include "bin2llvmir/optimizations/vtable/rtti_analysis.h"
#include "bin2llvmir/providers/config.h"

namespace bin2llvmir {

/**
 * One item in virtual table.
 * Item must have at least address set.
 * If there is a function on this address, it can be also set.
 * However, it is possible that function on address was not yet detected.
 * In such a case, we can use this virtual table entry to detect function.
 */
class VtableItem
{
	public:
		VtableItem(tl_cpputils::Address a, llvm::Function* f = nullptr);

	public:
		tl_cpputils::Address address;
		llvm::Function* function = nullptr;
};

/**
 * Virtual table comes in two flavors: 1) gcc&clang, 2) MSVC.
 * This is a base class for both of them.
 */
class Vtable
{
	public:
		Vtable(tl_cpputils::Address a);
		virtual ~Vtable() {}

		virtual std::string getName() const;
		friend std::ostream& operator<<(std::ostream &out, const Vtable &v);

	public:
		tl_cpputils::Address vtableAddress;
		std::vector<VtableItem> virtualFncAddresses;
		llvm::GlobalVariable* global = nullptr;
};

/**
 * gcc&clang virtual table sturcture ( [] means array of entries ):
 *
 *   [virtual call (vcall) offsets]
 *   [virtual base (vbase) offsets]
 *   offset to top
 *   typeinfo (RTTI) pointer
 *   [virtual function pointers] <- vtable address in instances points here
 *
 */
class VtableGcc : public Vtable
{
	public:
		VtableGcc(tl_cpputils::Address a);

		friend std::ostream& operator<<(std::ostream &out, const VtableGcc &v);

	public:
		std::vector<int> vcallOffsets; ///< TODO: not set/used right now
		std::vector<int> vbaseOffsets; ///< TODO: not set/used right now
		int topOffset = 0;             ///< TODO: not set/used right now
		tl_cpputils::Address rttiAddress;
		// Vtable::virtualFncAddresses

		ClassTypeInfo* rtti = nullptr;
};

/**
 * MSVC virtual table sturcture ( [] means array of entries ):
 *
 *   complete object locator address
 *   [virtual function pointers] <- vtable address in instances points here
 *
 */
class VtableMsvc : public Vtable
{
	public:
		VtableMsvc(tl_cpputils::Address a);

		friend std::ostream& operator<<(std::ostream &out, const VtableMsvc &v);

	public:
		tl_cpputils::Address objLocatorAddress;
		// Vtable::virtualFncAddresses

		RTTICompleteObjectLocator* rtti = nullptr;
};

/**
 * This pass finds vtables in the binary file.
 * Vtables may have slightly different structure (see class Vtable).
 *
 * To find both flavors with the single algorithm, we use these constraints:
 *
 * 1) We search for continuous sequence of references into code section/segment.
 * 2) At leas one reference must point to function. At the end, all references
 *    must be functions, but it is possible that the decompiler did not detect
 *    them so far (stripped inputs) and some references are just to instructions.
 *    This way, we can use vtables to detect functions and them rebuild them to
 *    fix references.
 * 3) We iterate through all instructions and find stores that work with vtable
 *    items.
 */
class VtableAnalysis : public llvm::ModulePass
{
	public:
		static char ID;
		VtableAnalysis();
		~VtableAnalysis();
		virtual void getAnalysisUsage(llvm::AnalysisUsage &AU) const override;
		virtual bool runOnModule(llvm::Module &) override;

	public:
		using VtableMap           = std::map<tl_cpputils::Address, Vtable*>;
		using InstrToReferenceMap = std::map<llvm::Instruction*, tl_cpputils::Address>;
		using AddressSet          = std::set<tl_cpputils::Address>;

	public:
		const VtableMap& getVtableMap() const;
		Vtable* getVtableOnAddress(tl_cpputils::Address a) const;

	private:
		void detectVtablesInData();
		void parseVtables();
		VtableGcc *createVtableGcc(tl_cpputils::Address a);
		VtableMsvc *createVtableMsvc(tl_cpputils::Address a);
		bool fillVtable(tl_cpputils::Address a, Vtable &vt);

		void createFunctions();
		void createVtableStructures();
		void setVtablesToConfig();

	public:
		RttiAnalysis rttiAnalysis;

	private:
		VtableMap vtableMap;
		InstrToReferenceMap instrToRef;
		AddressSet possibleVtableAddresses;
		AddressSet processedAddresses;

		llvm::Module *module = nullptr;
		Config* config = nullptr;
		FileImage* objf = nullptr;
		DataReferences* RA = nullptr;

		bool msvc = false;
		bool gcc = false;
};

} // namespace bin2llvmir

#endif
