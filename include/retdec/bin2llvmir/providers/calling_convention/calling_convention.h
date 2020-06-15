/**
 * @file include/retdec/bin2llvmir/providers/calling_convention/calling_convention.h
 * @brief Calling convention information.
 * @copyright (c) 2019 Avast Software, licensed under the MIT license
 */

#ifndef RETDEC_BIN2LLVMIR_PROVIDERS_CALL_CONV_CALL_CONV_H
#define RETDEC_BIN2LLVMIR_PROVIDERS_CALL_CONV_CALL_CONV_H

#include <vector>

#include <llvm/IR/Module.h>

#include "retdec/common/calling_convention.h"

namespace retdec {
namespace bin2llvmir {

class Abi;

class CallingConvention
{
	// Typedefs.
	//
	public:
		typedef std::unique_ptr<CallingConvention> Ptr;
		typedef retdec::common::CallingConventionID ID;

		typedef Ptr (*ConstructorMethod)(const Abi*);

	// Constants.
	//
	public:
		static const bool RTL;
		static const bool LTR;

	// Ctors, dtors.
	//
	public:
		CallingConvention(const Abi* abi);
		virtual ~CallingConvention() = default;

	// Registers.
	//
	public:
		const std::vector<uint32_t>& getParamRegisters() const;
		const std::vector<uint32_t>& getParamFPRegisters() const;
		const std::vector<uint32_t>& getParamDoubleRegisters() const;
		const std::vector<uint32_t>& getParamVectorRegisters() const;

		const std::vector<uint32_t>& getReturnRegisters() const;
		const std::vector<uint32_t>& getReturnFPRegisters() const;
		const std::vector<uint32_t>& getReturnDoubleRegisters() const;
		const std::vector<uint32_t>& getReturnVectorRegisters() const;

		bool usesFPRegistersForParameters() const;

		std::size_t getMaxNumOfRegsPerParam() const;
		std::size_t getMaxNumOfFPRegsPerParam() const;
		std::size_t getMaxNumOfDoubleRegsPerParam() const;
		std::size_t getMaxNumOfVectorRegsPerParam() const;

		std::size_t getMaxNumOfRegsPerReturn() const;
		std::size_t getMaxNumOfFPRegsPerReturn() const;
		std::size_t getMaxNumOfDoubleRegsPerReturn() const;
		std::size_t getMaxNumOfVectorRegsPerReturn() const;

	// Stacks.
	public:
		bool getStackParamOrder() const;
		bool usesStackForParameters() const;
		bool passesLargeObjectsByReference() const;
		bool respectsRegisterCouples() const;

		virtual std::size_t getMaxBytesPerStackParam() const;

	// Values.
	public:
		virtual bool valueCanBeParameter(const llvm::Value* val) const;
		virtual bool canHoldReturnValue(const llvm::Value* val) const;

	// Private data - misc.
	//
	protected:
		const Abi* _abi;
		CallingConvention::ID _ccType;

	// Private data - registers.
	//
	protected:
		std::vector<uint32_t> _paramRegs {};
		std::vector<uint32_t> _paramFPRegs {};
		std::vector<uint32_t> _paramDoubleRegs {};
		std::vector<uint32_t> _paramVectorRegs {};

		std::vector<uint32_t> _returnRegs {};
		std::vector<uint32_t> _returnFPRegs {};
		std::vector<uint32_t> _returnDoubleRegs {};
		std::vector<uint32_t> _returnVectorRegs {};

	// Private data - registers informational.
	//
	protected:
		size_t _numOfRegsPerParam = 1;
		size_t _numOfFPRegsPerParam = 1;
		size_t _numOfDoubleRegsPerParam = 1;
		size_t _numOfVectorRegsPerParam = 1;

		size_t _numOfRegsPerReturn = 1;
		size_t _numOfFPRegsPerReturn = 1;
		size_t _numOfDoubleRegsPerReturn = 1;
		size_t _numOfVectorRegsPerReturn = 1;

	// Private data - stacks informational.
	//
	protected:
		bool _stackParamOrder = RTL;
		bool _largeObjectsPassedByReference = false;
		bool _respectsRegCouples = false;
};

class CallingConventionProvider
{
	// Private constructor.
	//
	private:
		CallingConventionProvider();

	// Destructor, singleton method.
	public:
		static CallingConventionProvider* getProvider();
		static void clear();

	// Factory methods.
	public:
		void registerCC(
			const CallingConvention::ID& cc,
			const CallingConvention::ConstructorMethod& con);

		CallingConvention::Ptr createCallingConvention(
					const CallingConvention::ID& cc,
					const Abi* a) const;

	// Private data - constrctor methods.
	private:
		std::vector<CallingConvention::ConstructorMethod> _id2cc;

};

} // namespace bin2llvmir
} // namespace retdec

#endif
