/**
* @file include/retdec/bin2llvmir/optimizations/param_return/filter/filter.h
* @brief Filters potential values according to calling convention.
* @copyright (c) 2019 Avast Software, licensed under the MIT license
*/

#ifndef RETDEC_BIN2LLVMIR_OPTIMIZATIONS_PARAM_RETURN_FILTER_FILTER_H
#define RETDEC_BIN2LLVMIR_OPTIMIZATIONS_PARAM_RETURN_FILTER_FILTER_H

#include <llvm/IR/Instructions.h>

#include "retdec/bin2llvmir/providers/abi/abi.h"
#include "retdec/bin2llvmir/providers/calling_convention/calling_convention.h"
#include "retdec/bin2llvmir/optimizations/param_return/collector/collector.h"
#include "retdec/bin2llvmir/optimizations/param_return/data_entries.h"

namespace retdec {
namespace bin2llvmir {

class FilterableLayout
{
	public:
		enum class Order {
			ORD_GPR,
			ORD_GPR_GROUP,
			ORD_FPR,
			ORD_FPR_GROUP,
			ORD_DOUBR,
			ORD_DOUBR_GROUP,
			ORD_VECR,
			ORD_VECR_GROUP,
			ORD_STACK,
			ORD_STACK_GROUP
		};

	public:
		std::vector<uint32_t> gpRegisters;
		std::vector<uint32_t> fpRegisters;
		std::vector<uint32_t> doubleRegisters;
		std::vector<uint32_t> vectorRegisters;
		std::vector<llvm::Value*> stacks;
		std::vector<llvm::Type*> knownTypes;
		std::vector<Order> knownOrder;
};

typedef FilterableLayout::Order OrderID;

class Filter
{
	public:
		typedef std::unique_ptr<Filter> Ptr;

	public:
		Filter(const Abi* _abi, const CallingConvention* _cc);
		virtual ~Filter() = default;

		void filterDefinition(DataFlowEntry* de) const;
		void filterCalls(DataFlowEntry* de) const;
		void filterCallsVariadic(
				DataFlowEntry* de,
				const Collector* collector) const;

		void estimateRetValue(DataFlowEntry* de) const;

	protected:
		virtual void filterDefinitionArgs(
				FilterableLayout& args,
				bool isVoidarg) const;

		virtual void filterCallArgs(
				FilterableLayout& args,
				bool isVoidarg) const;

		virtual void filterCallArgsByDefLayout(
				FilterableLayout& args,
				const FilterableLayout& def) const;

		virtual void filterRets(
				FilterableLayout& rets) const;

		virtual void filterRetsByDefLayout(
				FilterableLayout& args,
				const FilterableLayout& def) const;

		virtual void filterArgsByKnownTypes(FilterableLayout& lay) const;
		virtual void filterRetsByKnownTypes(FilterableLayout& lay) const;

	protected:
		void leaveCommonArgs(
			std::vector<FilterableLayout>& allArgs) const;

		void leaveCommonRets(
			std::vector<FilterableLayout>& allRets) const;

		void leaveCommon(
			std::vector<FilterableLayout>& allRets) const;

		void orderFiterableLayout(FilterableLayout& lay) const;

		void orderStacks(
			std::vector<llvm::Value*>& stacks,
			bool asc = true) const;

		void orderRegistersBy(
			std::vector<uint32_t>& regs,
			const std::vector<uint32_t>& orderedVector) const;

	protected:
		FilterableLayout createArgsFilterableLayout(
			const std::vector<llvm::Value*>& group,
			const std::vector<llvm::Type*>& knownTypes) const;

		FilterableLayout createRetsFilterableLayout(
			const std::vector<llvm::Value*>& group,
			llvm::Type* knownType) const;

		FilterableLayout createRetsFilterableLayout(
			const std::vector<llvm::Value*>& group,
			const std::vector<llvm::Type*>& knownTypes) const;

		virtual FilterableLayout separateArgValues(
			const std::vector<llvm::Value*>& paramValues) const;

		virtual FilterableLayout separateRetValues(
			const std::vector<llvm::Value*>& paramValues) const;

		virtual std::vector<llvm::Value*> createGroupedArgValues(
			const FilterableLayout& lay) const;

		virtual std::vector<llvm::Value*> createGroupedRetValues(
			const FilterableLayout& lay) const;

		FilterableLayout separateValues(
			const std::vector<llvm::Value*>& paramValues,
			const std::vector<uint32_t>& gpRegs,
			const std::vector<uint32_t>& fpRegs,
			const std::vector<uint32_t>& doubleRegs,
			const std::vector<uint32_t>& vecRegs) const;

		std::vector<llvm::Value*> createGroupedValues(
			const FilterableLayout& lay) const;

		std::vector<llvm::Type*> expandTypes(
			const std::vector<llvm::Type*>& types) const;

	protected:
		std::size_t fetchGPRegsForType(
				llvm::Type* type,
				FilterableLayout& lay) const;

		std::size_t fetchFPRegsForType(
				llvm::Type* type,
				FilterableLayout& lay) const;

		std::size_t fetchDoubleRegsForType(
				llvm::Type* type,
				FilterableLayout& lay) const;

		std::size_t fetchVecRegsForType(
				llvm::Type* type,
				FilterableLayout& lay) const;

		std::size_t fetchRegsForType(
				llvm::Type* type,
				std::vector<uint32_t>& store,
				const std::vector<uint32_t>& regs,
				std::size_t maxRegsPerObject) const;

	protected:
		std::size_t getNumberOfStacksForType(llvm::Type* type) const;

	protected:
		void leaveOnlyPositiveStacks(FilterableLayout& lay) const;
		void leaveOnlyContinuousStack(FilterableLayout& lay) const;
		void leaveOnlyContinuousArgRegisters(FilterableLayout& lay) const;
		void leaveOnlyContinuousRetRegisters(FilterableLayout& lay) const;
		void leaveSameStacks(FilterableLayout& lay, const FilterableLayout& fig) const;

		void leaveOnlyContinuousRegisters(
				std::vector<uint32_t>& regs,
				const std::vector<uint32_t>& templRegs) const;

		void createContinuousArgRegisters(FilterableLayout& lay) const;

	protected:
		const Abi* _abi;
		const CallingConvention* _cc;
};

class FilterProvider
{
	public:
		static Filter::Ptr createFilter(Abi* abi, const CallingConvention::ID& id);
};

}
}

#endif
