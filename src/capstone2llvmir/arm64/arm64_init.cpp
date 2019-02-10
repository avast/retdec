/**
 * @file src/capstone2llvmir/arm64/arm64_init.cpp
 * @brief Initializations for ARM64 implementation of @c Capstone2LlvmIrTranslator.
 * @copyright (c) 2017 Avast Software, licensed under the MIT license
 */

#include "capstone2llvmir/arm64/arm64_impl.h"

namespace retdec {
namespace capstone2llvmir {

//
//==============================================================================
// Pure virtual methods from Capstone2LlvmIrTranslator_impl
//==============================================================================
//

void Capstone2LlvmIrTranslatorArm64_impl::initializeArchSpecific()
{
	// Nothing.
}

void Capstone2LlvmIrTranslatorArm64_impl::initializeRegNameMap()
{
	std::map<uint32_t, std::string> r2n =
	{
			{ARM64_REG_CPSR_N, "cpsr_n"}, // Negative
			{ARM64_REG_CPSR_Z, "cpsr_z"}, // Zero
			{ARM64_REG_CPSR_C, "cpsr_c"}, // Carry
			{ARM64_REG_CPSR_V, "cpsr_v"}, // Overflow
			{ARM64_REG_PC, "pc"},         // Program counter
	};

	_reg2name = std::move(r2n);
}

void Capstone2LlvmIrTranslatorArm64_impl::initializeRegTypeMap()
{
	auto* i1 = llvm::IntegerType::getInt1Ty(_module->getContext());
	auto* i32 = llvm::IntegerType::getInt32Ty(_module->getContext());
	auto* defTy = getDefaultType();

	std::map<uint32_t, llvm::Type*> r2t =
	{
		// General purpose registers.
		//
		{ARM64_REG_X0, defTy},
		{ARM64_REG_X1, defTy},
		{ARM64_REG_X2, defTy},
		{ARM64_REG_X3, defTy},
		{ARM64_REG_X4, defTy},
		{ARM64_REG_X5, defTy},
		{ARM64_REG_X6, defTy},
		{ARM64_REG_X7, defTy},
		{ARM64_REG_X8, defTy},
		{ARM64_REG_X9, defTy},
		{ARM64_REG_X10, defTy},
		{ARM64_REG_X11, defTy},
		{ARM64_REG_X12, defTy},
		{ARM64_REG_X13, defTy},
		{ARM64_REG_X14, defTy},
		{ARM64_REG_X15, defTy},
		{ARM64_REG_X16, defTy},
		{ARM64_REG_X17, defTy},
		{ARM64_REG_X18, defTy},
		{ARM64_REG_X19, defTy},
		{ARM64_REG_X20, defTy},
		{ARM64_REG_X21, defTy},
		{ARM64_REG_X22, defTy},
		{ARM64_REG_X23, defTy},
		{ARM64_REG_X24, defTy},
		{ARM64_REG_X25, defTy},
		{ARM64_REG_X26, defTy},
		{ARM64_REG_X27, defTy},
		{ARM64_REG_X28, defTy},

		// Lower 32 bits of 64{xN} regs
		//
		{ARM64_REG_W0, i32},
		{ARM64_REG_W1, i32},
		{ARM64_REG_W2, i32},
		{ARM64_REG_W3, i32},
		{ARM64_REG_W4, i32},
		{ARM64_REG_W5, i32},
		{ARM64_REG_W6, i32},
		{ARM64_REG_W7, i32},
		{ARM64_REG_W8, i32},
		{ARM64_REG_W9, i32},
		{ARM64_REG_W10, i32},
		{ARM64_REG_W11, i32},
		{ARM64_REG_W12, i32},
		{ARM64_REG_W13, i32},
		{ARM64_REG_W14, i32},
		{ARM64_REG_W15, i32},
		{ARM64_REG_W16, i32},
		{ARM64_REG_W17, i32},
		{ARM64_REG_W18, i32},
		{ARM64_REG_W19, i32},
		{ARM64_REG_W20, i32},
		{ARM64_REG_W21, i32},
		{ARM64_REG_W22, i32},
		{ARM64_REG_W23, i32},
		{ARM64_REG_W24, i32},
		{ARM64_REG_W25, i32},
		{ARM64_REG_W26, i32},
		{ARM64_REG_W27, i32},
		{ARM64_REG_W28, i32},
		{ARM64_REG_W29, i32},
		{ARM64_REG_W30, i32},

		// Special registers.

		// FP Frame pointer
		{ARM64_REG_X29, defTy},

		// LP Link register
		{ARM64_REG_X30, defTy},

		// Stack pointer
		{ARM64_REG_SP, defTy},
		{ARM64_REG_WSP, i32},

		// Zero
		{ARM64_REG_XZR, defTy},
		{ARM64_REG_WZR, i32},

		// CPSR flags.
		//
		{ARM64_REG_CPSR_N, i1},
		{ARM64_REG_CPSR_Z, i1},
		{ARM64_REG_CPSR_C, i1},
		{ARM64_REG_CPSR_V, i1},

		// Program counter.
		{ARM64_REG_PC, defTy},
	};

	_reg2type = std::move(r2t);
}

void Capstone2LlvmIrTranslatorArm64_impl::initializePseudoCallInstructionIDs()
{
	_callInsnIds =
	{
		ARM64_INS_BL,
	};

	_returnInsnIds =
	{
		ARM64_INS_RET,
	};

	_branchInsnIds =
	{

	};

	_condBranchInsnIds =
	{

	};

	_controlFlowInsnIds =
	{

	};
}

void Capstone2LlvmIrTranslatorArm64_impl::initializeRegistersParentMapToOther(
		const std::vector<arm64_reg>& rs,
		arm64_reg other)
{
	for (auto r : rs)
	{
		assert(r < _reg2parentMap.size());
		_reg2parentMap[r] = other;
	}
}


void Capstone2LlvmIrTranslatorArm64_impl::initializeRegistersParentMap()
{
	// Last element in vector is its own parent.
	std::vector<std::vector<arm64_reg>> rss =
	{
			{ARM64_REG_W0, ARM64_REG_X0},
			{ARM64_REG_W1, ARM64_REG_X1},
			{ARM64_REG_W2, ARM64_REG_X2},
			{ARM64_REG_W3, ARM64_REG_X3},
			{ARM64_REG_W4, ARM64_REG_X4},
			{ARM64_REG_W5, ARM64_REG_X5},
			{ARM64_REG_W6, ARM64_REG_X6},
			{ARM64_REG_W7, ARM64_REG_X7},
			{ARM64_REG_W8, ARM64_REG_X8},
			{ARM64_REG_W9, ARM64_REG_X9},
			{ARM64_REG_W10, ARM64_REG_X10},
			{ARM64_REG_W11, ARM64_REG_X11},
			{ARM64_REG_W12, ARM64_REG_X12},
			{ARM64_REG_W13, ARM64_REG_X13},
			{ARM64_REG_W14, ARM64_REG_X14},
			{ARM64_REG_W15, ARM64_REG_X15},
			{ARM64_REG_W16, ARM64_REG_X16},
			{ARM64_REG_W17, ARM64_REG_X17},
			{ARM64_REG_W18, ARM64_REG_X18},
			{ARM64_REG_W19, ARM64_REG_X19},
			{ARM64_REG_W20, ARM64_REG_X20},
			{ARM64_REG_W21, ARM64_REG_X21},
			{ARM64_REG_W22, ARM64_REG_X22},
			{ARM64_REG_W23, ARM64_REG_X23},
			{ARM64_REG_W24, ARM64_REG_X24},
			{ARM64_REG_W25, ARM64_REG_X25},
			{ARM64_REG_W26, ARM64_REG_X26},
			{ARM64_REG_W27, ARM64_REG_X27},
			{ARM64_REG_W28, ARM64_REG_X28},
			{ARM64_REG_W29, ARM64_REG_X29},
			{ARM64_REG_W30, ARM64_REG_X30},

			{ARM64_REG_WSP, ARM64_REG_SP},
			{ARM64_REG_WZR, ARM64_REG_XZR}
	};

	for (std::vector<arm64_reg>& rs : rss)
	{
		initializeRegistersParentMapToOther(rs, rs.back());
	}
}

//
//==============================================================================
// Instruction translation map initialization.
//==============================================================================
//

std::map<
	std::size_t,
	void (Capstone2LlvmIrTranslatorArm64_impl::*)(
			cs_insn* i,
			cs_arm64*,
			llvm::IRBuilder<>&)>
Capstone2LlvmIrTranslatorArm64_impl::_i2fm =
{
	{ARM_INS_INVALID, nullptr},

	{ARM64_INS_ABS, nullptr},
	{ARM64_INS_ADC, &Capstone2LlvmIrTranslatorArm64_impl::translateAdc},
	{ARM64_INS_ADDHN, nullptr},
	{ARM64_INS_ADDHN2, nullptr},
	{ARM64_INS_ADDP, nullptr},
	{ARM64_INS_ADD, &Capstone2LlvmIrTranslatorArm64_impl::translateAdd},
	{ARM64_INS_ADDV, nullptr},
	{ARM64_INS_ADR, &Capstone2LlvmIrTranslatorArm64_impl::translateAdr},
	{ARM64_INS_ADRP, &Capstone2LlvmIrTranslatorArm64_impl::translateAdr},
	{ARM64_INS_AESD, nullptr},
	{ARM64_INS_AESE, nullptr},
	{ARM64_INS_AESIMC, nullptr},
	{ARM64_INS_AESMC, nullptr},
	{ARM64_INS_AND, &Capstone2LlvmIrTranslatorArm64_impl::translateAnd},
	{ARM64_INS_ASR, &Capstone2LlvmIrTranslatorArm64_impl::translateShifts},
	{ARM64_INS_B, &Capstone2LlvmIrTranslatorArm64_impl::translateB},
	{ARM64_INS_BFM, nullptr},
	{ARM64_INS_BIC, nullptr},
	{ARM64_INS_BIF, nullptr},
	{ARM64_INS_BIT, nullptr},
	{ARM64_INS_BL, &Capstone2LlvmIrTranslatorArm64_impl::translateBl},
	{ARM64_INS_BLR, &Capstone2LlvmIrTranslatorArm64_impl::translateBr},
	{ARM64_INS_BR, &Capstone2LlvmIrTranslatorArm64_impl::translateBr},
	{ARM64_INS_BRK, nullptr},
	{ARM64_INS_BSL, nullptr},
	{ARM64_INS_CBNZ, &Capstone2LlvmIrTranslatorArm64_impl::translateCbnz},
	{ARM64_INS_CBZ, &Capstone2LlvmIrTranslatorArm64_impl::translateCbnz},
	{ARM64_INS_CCMN, nullptr},
	{ARM64_INS_CCMP, nullptr},
	{ARM64_INS_CLREX, nullptr},
	{ARM64_INS_CLS, nullptr},
	{ARM64_INS_CLZ, nullptr},
	{ARM64_INS_CMEQ, nullptr},
	{ARM64_INS_CMGE, nullptr},
	{ARM64_INS_CMGT, nullptr},
	{ARM64_INS_CMHI, nullptr},
	{ARM64_INS_CMHS, nullptr},
	{ARM64_INS_CMLE, nullptr},
	{ARM64_INS_CMLT, nullptr},
	{ARM64_INS_CMTST, nullptr},
	{ARM64_INS_CNT, nullptr},
	{ARM64_INS_MOV, &Capstone2LlvmIrTranslatorArm64_impl::translateMov},
	{ARM64_INS_CRC32B, nullptr},
	{ARM64_INS_CRC32CB, nullptr},
	{ARM64_INS_CRC32CH, nullptr},
	{ARM64_INS_CRC32CW, nullptr},
	{ARM64_INS_CRC32CX, nullptr},
	{ARM64_INS_CRC32H, nullptr},
	{ARM64_INS_CRC32W, nullptr},
	{ARM64_INS_CRC32X, nullptr},
	{ARM64_INS_CSEL, &Capstone2LlvmIrTranslatorArm64_impl::translateCsel},
	{ARM64_INS_CSINC, nullptr},
	{ARM64_INS_CSINV, nullptr},
	{ARM64_INS_CSNEG, nullptr},
	{ARM64_INS_DCPS1, nullptr},
	{ARM64_INS_DCPS2, nullptr},
	{ARM64_INS_DCPS3, nullptr},
	{ARM64_INS_DMB, nullptr},
	{ARM64_INS_DRPS, nullptr},
	{ARM64_INS_DSB, nullptr},
	{ARM64_INS_DUP, nullptr},
	{ARM64_INS_EON, nullptr},
	{ARM64_INS_EOR, nullptr},
	{ARM64_INS_ERET, nullptr},
	{ARM64_INS_EXTR, nullptr},
	{ARM64_INS_EXT, nullptr},
	{ARM64_INS_FABD, nullptr},
	{ARM64_INS_FABS, nullptr},
	{ARM64_INS_FACGE, nullptr},
	{ARM64_INS_FACGT, nullptr},
	{ARM64_INS_FADD, nullptr},
	{ARM64_INS_FADDP, nullptr},
	{ARM64_INS_FCCMP, nullptr},
	{ARM64_INS_FCCMPE, nullptr},
	{ARM64_INS_FCMEQ, nullptr},
	{ARM64_INS_FCMGE, nullptr},
	{ARM64_INS_FCMGT, nullptr},
	{ARM64_INS_FCMLE, nullptr},
	{ARM64_INS_FCMLT, nullptr},
	{ARM64_INS_FCMP, nullptr},
	{ARM64_INS_FCMPE, nullptr},
	{ARM64_INS_FCSEL, nullptr},
	{ARM64_INS_FCVTAS, nullptr},
	{ARM64_INS_FCVTAU, nullptr},
	{ARM64_INS_FCVT, nullptr},
	{ARM64_INS_FCVTL, nullptr},
	{ARM64_INS_FCVTL2, nullptr},
	{ARM64_INS_FCVTMS, nullptr},
	{ARM64_INS_FCVTMU, nullptr},
	{ARM64_INS_FCVTNS, nullptr},
	{ARM64_INS_FCVTNU, nullptr},
	{ARM64_INS_FCVTN, nullptr},
	{ARM64_INS_FCVTN2, nullptr},
	{ARM64_INS_FCVTPS, nullptr},
	{ARM64_INS_FCVTPU, nullptr},
	{ARM64_INS_FCVTXN, nullptr},
	{ARM64_INS_FCVTXN2, nullptr},
	{ARM64_INS_FCVTZS, nullptr},
	{ARM64_INS_FCVTZU, nullptr},
	{ARM64_INS_FDIV, nullptr},
	{ARM64_INS_FMADD, nullptr},
	{ARM64_INS_FMAX, nullptr},
	{ARM64_INS_FMAXNM, nullptr},
	{ARM64_INS_FMAXNMP, nullptr},
	{ARM64_INS_FMAXNMV, nullptr},
	{ARM64_INS_FMAXP, nullptr},
	{ARM64_INS_FMAXV, nullptr},
	{ARM64_INS_FMIN, nullptr},
	{ARM64_INS_FMINNM, nullptr},
	{ARM64_INS_FMINNMP, nullptr},
	{ARM64_INS_FMINNMV, nullptr},
	{ARM64_INS_FMINP, nullptr},
	{ARM64_INS_FMINV, nullptr},
	{ARM64_INS_FMLA, nullptr},
	{ARM64_INS_FMLS, nullptr},
	{ARM64_INS_FMOV, nullptr},
	{ARM64_INS_FMSUB, nullptr},
	{ARM64_INS_FMUL, nullptr},
	{ARM64_INS_FMULX, nullptr},
	{ARM64_INS_FNEG, nullptr},
	{ARM64_INS_FNMADD, nullptr},
	{ARM64_INS_FNMSUB, nullptr},
	{ARM64_INS_FNMUL, nullptr},
	{ARM64_INS_FRECPE, nullptr},
	{ARM64_INS_FRECPS, nullptr},
	{ARM64_INS_FRECPX, nullptr},
	{ARM64_INS_FRINTA, nullptr},
	{ARM64_INS_FRINTI, nullptr},
	{ARM64_INS_FRINTM, nullptr},
	{ARM64_INS_FRINTN, nullptr},
	{ARM64_INS_FRINTP, nullptr},
	{ARM64_INS_FRINTX, nullptr},
	{ARM64_INS_FRINTZ, nullptr},
	{ARM64_INS_FRSQRTE, nullptr},
	{ARM64_INS_FRSQRTS, nullptr},
	{ARM64_INS_FSQRT, nullptr},
	{ARM64_INS_FSUB, nullptr},
	{ARM64_INS_HINT, nullptr},
	{ARM64_INS_HLT, nullptr},
	{ARM64_INS_HVC, nullptr},
	{ARM64_INS_INS, nullptr},

	{ARM64_INS_ISB, nullptr},
	{ARM64_INS_LD1, nullptr},
	{ARM64_INS_LD1R, nullptr},
	{ARM64_INS_LD2R, nullptr},
	{ARM64_INS_LD2, nullptr},
	{ARM64_INS_LD3R, nullptr},
	{ARM64_INS_LD3, nullptr},
	{ARM64_INS_LD4, nullptr},
	{ARM64_INS_LD4R, nullptr},

	{ARM64_INS_LDARB, nullptr},
	{ARM64_INS_LDARH, nullptr},
	{ARM64_INS_LDAR, nullptr},
	{ARM64_INS_LDAXP, nullptr},
	{ARM64_INS_LDAXRB, nullptr},
	{ARM64_INS_LDAXRH, nullptr},
	{ARM64_INS_LDAXR, nullptr},
	{ARM64_INS_LDNP, nullptr},
	{ARM64_INS_LDP, &Capstone2LlvmIrTranslatorArm64_impl::translateLdp},
	{ARM64_INS_LDPSW, &Capstone2LlvmIrTranslatorArm64_impl::translateLdp},
	{ARM64_INS_LDRB, &Capstone2LlvmIrTranslatorArm64_impl::translateLdr},
	{ARM64_INS_LDR, &Capstone2LlvmIrTranslatorArm64_impl::translateLdr},
	{ARM64_INS_LDRH, &Capstone2LlvmIrTranslatorArm64_impl::translateLdr},
	{ARM64_INS_LDRSB, &Capstone2LlvmIrTranslatorArm64_impl::translateLdr},
	{ARM64_INS_LDRSH, &Capstone2LlvmIrTranslatorArm64_impl::translateLdr},
	{ARM64_INS_LDRSW, &Capstone2LlvmIrTranslatorArm64_impl::translateLdr},
	{ARM64_INS_LDTRB, nullptr},
	{ARM64_INS_LDTRH, nullptr},
	{ARM64_INS_LDTRSB, nullptr},

	{ARM64_INS_LDTRSH, nullptr},
	{ARM64_INS_LDTRSW, nullptr},
	{ARM64_INS_LDTR, nullptr},
	{ARM64_INS_LDURB, &Capstone2LlvmIrTranslatorArm64_impl::translateLdr},
	{ARM64_INS_LDUR, &Capstone2LlvmIrTranslatorArm64_impl::translateLdr},
	{ARM64_INS_LDURH, &Capstone2LlvmIrTranslatorArm64_impl::translateLdr},
	{ARM64_INS_LDURSB, &Capstone2LlvmIrTranslatorArm64_impl::translateLdr},
	{ARM64_INS_LDURSH, &Capstone2LlvmIrTranslatorArm64_impl::translateLdr},
	{ARM64_INS_LDURSW, &Capstone2LlvmIrTranslatorArm64_impl::translateLdr},
	{ARM64_INS_LDXP, nullptr},
	{ARM64_INS_LDXRB, nullptr},
	{ARM64_INS_LDXRH, nullptr},
	{ARM64_INS_LDXR, nullptr},
	{ARM64_INS_LSL, &Capstone2LlvmIrTranslatorArm64_impl::translateShifts},
	{ARM64_INS_LSR, &Capstone2LlvmIrTranslatorArm64_impl::translateShifts},
	{ARM64_INS_MADD, nullptr},
	{ARM64_INS_MLA, nullptr},
	{ARM64_INS_MLS, nullptr},
	{ARM64_INS_MOVI, nullptr},
	{ARM64_INS_MOVK, nullptr},
	{ARM64_INS_MOVN, nullptr},
	{ARM64_INS_MOVZ, &Capstone2LlvmIrTranslatorArm64_impl::translateMov},
	{ARM64_INS_MRS, nullptr},
	{ARM64_INS_MSR, nullptr},
	{ARM64_INS_MSUB, nullptr},
	{ARM64_INS_MUL, nullptr},
	{ARM64_INS_MVNI, nullptr},
	{ARM64_INS_NEG, nullptr},
	{ARM64_INS_NOT, nullptr},
	{ARM64_INS_ORN, nullptr},
	{ARM64_INS_ORR, nullptr},
	{ARM64_INS_PMULL2, nullptr},
	{ARM64_INS_PMULL, nullptr},
	{ARM64_INS_PMUL, nullptr},
	{ARM64_INS_PRFM, nullptr},
	{ARM64_INS_PRFUM, nullptr},
	{ARM64_INS_RADDHN, nullptr},
	{ARM64_INS_RADDHN2, nullptr},
	{ARM64_INS_RBIT, nullptr},
	{ARM64_INS_RET, &Capstone2LlvmIrTranslatorArm64_impl::translateRet},
	{ARM64_INS_REV16, nullptr},
	{ARM64_INS_REV32, nullptr},
	{ARM64_INS_REV64, nullptr},
	{ARM64_INS_REV, nullptr},
	{ARM64_INS_ROR, &Capstone2LlvmIrTranslatorArm64_impl::translateShifts},
	{ARM64_INS_RSHRN2, nullptr},
	{ARM64_INS_RSHRN, nullptr},
	{ARM64_INS_RSUBHN, nullptr},
	{ARM64_INS_RSUBHN2, nullptr},
	{ARM64_INS_SABAL2, nullptr},
	{ARM64_INS_SABAL, nullptr},

	{ARM64_INS_SABA, nullptr},
	{ARM64_INS_SABDL2, nullptr},
	{ARM64_INS_SABDL, nullptr},
	{ARM64_INS_SABD, nullptr},
	{ARM64_INS_SADALP, nullptr},
	{ARM64_INS_SADDLP, nullptr},
	{ARM64_INS_SADDLV, nullptr},
	{ARM64_INS_SADDL2, nullptr},
	{ARM64_INS_SADDL, nullptr},
	{ARM64_INS_SADDW2, nullptr},
	{ARM64_INS_SADDW, nullptr},
	{ARM64_INS_SBC, &Capstone2LlvmIrTranslatorArm64_impl::translateSbc},
	{ARM64_INS_SBFM, nullptr},
	{ARM64_INS_SCVTF, nullptr},
	{ARM64_INS_SDIV, nullptr},
	{ARM64_INS_SHA1C, nullptr},
	{ARM64_INS_SHA1H, nullptr},
	{ARM64_INS_SHA1M, nullptr},
	{ARM64_INS_SHA1P, nullptr},
	{ARM64_INS_SHA1SU0, nullptr},
	{ARM64_INS_SHA1SU1, nullptr},
	{ARM64_INS_SHA256H2, nullptr},
	{ARM64_INS_SHA256H, nullptr},
	{ARM64_INS_SHA256SU0, nullptr},
	{ARM64_INS_SHA256SU1, nullptr},
	{ARM64_INS_SHADD, nullptr},
	{ARM64_INS_SHLL2, nullptr},
	{ARM64_INS_SHLL, nullptr},
	{ARM64_INS_SHL, nullptr},
	{ARM64_INS_SHRN2, nullptr},
	{ARM64_INS_SHRN, nullptr},
	{ARM64_INS_SHSUB, nullptr},
	{ARM64_INS_SLI, nullptr},
	{ARM64_INS_SMADDL, nullptr},
	{ARM64_INS_SMAXP, nullptr},
	{ARM64_INS_SMAXV, nullptr},
	{ARM64_INS_SMAX, nullptr},
	{ARM64_INS_SMC, nullptr},
	{ARM64_INS_SMINP, nullptr},
	{ARM64_INS_SMINV, nullptr},
	{ARM64_INS_SMIN, nullptr},
	{ARM64_INS_SMLAL2, nullptr},
	{ARM64_INS_SMLAL, nullptr},
	{ARM64_INS_SMLSL2, nullptr},
	{ARM64_INS_SMLSL, nullptr},
	{ARM64_INS_SMOV, nullptr},
	{ARM64_INS_SMSUBL, nullptr},
	{ARM64_INS_SMULH, nullptr},
	{ARM64_INS_SMULL2, nullptr},
	{ARM64_INS_SMULL, nullptr},
	{ARM64_INS_SQABS, nullptr},
	{ARM64_INS_SQADD, nullptr},
	{ARM64_INS_SQDMLAL, nullptr},
	{ARM64_INS_SQDMLAL2, nullptr},
	{ARM64_INS_SQDMLSL, nullptr},
	{ARM64_INS_SQDMLSL2, nullptr},
	{ARM64_INS_SQDMULH, nullptr},
	{ARM64_INS_SQDMULL, nullptr},
	{ARM64_INS_SQDMULL2, nullptr},
	{ARM64_INS_SQNEG, nullptr},
	{ARM64_INS_SQRDMULH, nullptr},
	{ARM64_INS_SQRSHL, nullptr},
	{ARM64_INS_SQRSHRN, nullptr},
	{ARM64_INS_SQRSHRN2, nullptr},
	{ARM64_INS_SQRSHRUN, nullptr},
	{ARM64_INS_SQRSHRUN2, nullptr},
	{ARM64_INS_SQSHLU, nullptr},
	{ARM64_INS_SQSHL, nullptr},
	{ARM64_INS_SQSHRN, nullptr},
	{ARM64_INS_SQSHRN2, nullptr},
	{ARM64_INS_SQSHRUN, nullptr},
	{ARM64_INS_SQSHRUN2, nullptr},
	{ARM64_INS_SQSUB, nullptr},
	{ARM64_INS_SQXTN2, nullptr},
	{ARM64_INS_SQXTN, nullptr},
	{ARM64_INS_SQXTUN2, nullptr},
	{ARM64_INS_SQXTUN, nullptr},
	{ARM64_INS_SRHADD, nullptr},
	{ARM64_INS_SRI, nullptr},
	{ARM64_INS_SRSHL, nullptr},
	{ARM64_INS_SRSHR, nullptr},
	{ARM64_INS_SRSRA, nullptr},
	{ARM64_INS_SSHLL2, nullptr},
	{ARM64_INS_SSHLL, nullptr},
	{ARM64_INS_SSHL, nullptr},
	{ARM64_INS_SSHR, nullptr},
	{ARM64_INS_SSRA, nullptr},
	{ARM64_INS_SSUBL2, nullptr},
	{ARM64_INS_SSUBL, nullptr},
	{ARM64_INS_SSUBW2, nullptr},
	{ARM64_INS_SSUBW, nullptr},
	{ARM64_INS_ST1, nullptr},
	{ARM64_INS_ST2, nullptr},
	{ARM64_INS_ST3, nullptr},
	{ARM64_INS_ST4, nullptr},
	{ARM64_INS_STLRB, nullptr},
	{ARM64_INS_STLRH, nullptr},
	{ARM64_INS_STLR, nullptr},
	{ARM64_INS_STLXP, nullptr},
	{ARM64_INS_STLXRB, nullptr},
	{ARM64_INS_STLXRH, nullptr},
	{ARM64_INS_STLXR, nullptr},
	{ARM64_INS_STNP, nullptr},
	{ARM64_INS_STP, &Capstone2LlvmIrTranslatorArm64_impl::translateStp},
	{ARM64_INS_STRB, &Capstone2LlvmIrTranslatorArm64_impl::translateStr},
	{ARM64_INS_STR, &Capstone2LlvmIrTranslatorArm64_impl::translateStr},
	{ARM64_INS_STRH, &Capstone2LlvmIrTranslatorArm64_impl::translateStr},
	{ARM64_INS_STTRB, nullptr},
	{ARM64_INS_STTRH, nullptr},
	{ARM64_INS_STTR, nullptr},
	{ARM64_INS_STURB, nullptr},
	{ARM64_INS_STUR, &Capstone2LlvmIrTranslatorArm64_impl::translateStr},
	{ARM64_INS_STURH, nullptr},
	{ARM64_INS_STXP, nullptr},
	{ARM64_INS_STXRB, nullptr},
	{ARM64_INS_STXRH, nullptr},
	{ARM64_INS_STXR, nullptr},
	{ARM64_INS_SUBHN, nullptr},
	{ARM64_INS_SUBHN2, nullptr},
	{ARM64_INS_SUB, &Capstone2LlvmIrTranslatorArm64_impl::translateSub},
	{ARM64_INS_SUQADD, nullptr},
	{ARM64_INS_SVC, nullptr},
	{ARM64_INS_SYSL, nullptr},
	{ARM64_INS_SYS, nullptr},
	{ARM64_INS_TBL, nullptr},
	{ARM64_INS_TBNZ, &Capstone2LlvmIrTranslatorArm64_impl::translateTbnz},
	{ARM64_INS_TBX, nullptr},
	{ARM64_INS_TBZ, &Capstone2LlvmIrTranslatorArm64_impl::translateTbnz},
	{ARM64_INS_TRN1, nullptr},
	{ARM64_INS_TRN2, nullptr},
	{ARM64_INS_UABAL2, nullptr},
	{ARM64_INS_UABAL, nullptr},
	{ARM64_INS_UABA, nullptr},
	{ARM64_INS_UABDL2, nullptr},
	{ARM64_INS_UABDL, nullptr},
	{ARM64_INS_UABD, nullptr},
	{ARM64_INS_UADALP, nullptr},
	{ARM64_INS_UADDLP, nullptr},
	{ARM64_INS_UADDLV, nullptr},
	{ARM64_INS_UADDL2, nullptr},
	{ARM64_INS_UADDL, nullptr},
	{ARM64_INS_UADDW2, nullptr},
	{ARM64_INS_UADDW, nullptr},
	{ARM64_INS_UBFM, nullptr},
	{ARM64_INS_UCVTF, nullptr},
	{ARM64_INS_UDIV, nullptr},
	{ARM64_INS_UHADD, nullptr},
	{ARM64_INS_UHSUB, nullptr},
	{ARM64_INS_UMADDL, nullptr},
	{ARM64_INS_UMAXP, nullptr},
	{ARM64_INS_UMAXV, nullptr},
	{ARM64_INS_UMAX, nullptr},
	{ARM64_INS_UMINP, nullptr},
	{ARM64_INS_UMINV, nullptr},
	{ARM64_INS_UMIN, nullptr},
	{ARM64_INS_UMLAL2, nullptr},
	{ARM64_INS_UMLAL, nullptr},
	{ARM64_INS_UMLSL2, nullptr},
	{ARM64_INS_UMLSL, nullptr},
	{ARM64_INS_UMOV, nullptr},
	{ARM64_INS_UMSUBL, nullptr},
	{ARM64_INS_UMULH, nullptr},
	{ARM64_INS_UMULL2, nullptr},
	{ARM64_INS_UMULL, nullptr},
	{ARM64_INS_UQADD, nullptr},
	{ARM64_INS_UQRSHL, nullptr},
	{ARM64_INS_UQRSHRN, nullptr},
	{ARM64_INS_UQRSHRN2, nullptr},
	{ARM64_INS_UQSHL, nullptr},
	{ARM64_INS_UQSHRN, nullptr},
	{ARM64_INS_UQSHRN2, nullptr},
	{ARM64_INS_UQSUB, nullptr},
	{ARM64_INS_UQXTN2, nullptr},
	{ARM64_INS_UQXTN, nullptr},
	{ARM64_INS_URECPE, nullptr},
	{ARM64_INS_URHADD, nullptr},
	{ARM64_INS_URSHL, nullptr},
	{ARM64_INS_URSHR, nullptr},
	{ARM64_INS_URSQRTE, nullptr},
	{ARM64_INS_URSRA, nullptr},
	{ARM64_INS_USHLL2, nullptr},
	{ARM64_INS_USHLL, nullptr},
	{ARM64_INS_USHL, nullptr},
	{ARM64_INS_USHR, nullptr},
	{ARM64_INS_USQADD, nullptr},
	{ARM64_INS_USRA, nullptr},
	{ARM64_INS_USUBL2, nullptr},
	{ARM64_INS_USUBL, nullptr},
	{ARM64_INS_USUBW2, nullptr},
	{ARM64_INS_USUBW, nullptr},
	{ARM64_INS_UZP1, nullptr},
	{ARM64_INS_UZP2, nullptr},
	{ARM64_INS_XTN2, nullptr},
	{ARM64_INS_XTN, nullptr},
	{ARM64_INS_ZIP1, nullptr},
	{ARM64_INS_ZIP2, nullptr},

	// alias insn
	{ARM64_INS_MNEG, nullptr},
	{ARM64_INS_UMNEGL, nullptr},
	{ARM64_INS_SMNEGL, nullptr},
	{ARM64_INS_NOP, nullptr},
	{ARM64_INS_YIELD, nullptr},
	{ARM64_INS_WFE, nullptr},
	{ARM64_INS_WFI, nullptr},
	{ARM64_INS_SEV, nullptr},
	{ARM64_INS_SEVL, nullptr},
	{ARM64_INS_NGC, nullptr},
	{ARM64_INS_SBFIZ, nullptr},
	{ARM64_INS_UBFIZ, nullptr},
	{ARM64_INS_SBFX, nullptr},
	{ARM64_INS_UBFX, nullptr},
	{ARM64_INS_BFI, nullptr},
	{ARM64_INS_BFXIL, nullptr},
	{ARM64_INS_CMN, &Capstone2LlvmIrTranslatorArm64_impl::translateAdd},
	{ARM64_INS_MVN, &Capstone2LlvmIrTranslatorArm64_impl::translateMov},
	{ARM64_INS_TST, nullptr},
	{ARM64_INS_CSET, nullptr},
	{ARM64_INS_CINC, nullptr},
	{ARM64_INS_CSETM, nullptr},
	{ARM64_INS_CINV, nullptr},
	{ARM64_INS_CNEG, nullptr},
	{ARM64_INS_SXTB, nullptr},
	{ARM64_INS_SXTH, nullptr},
	{ARM64_INS_SXTW, nullptr},
	{ARM64_INS_CMP, &Capstone2LlvmIrTranslatorArm64_impl::translateSub},
	{ARM64_INS_UXTB, nullptr},
	{ARM64_INS_UXTH, nullptr},
	{ARM64_INS_UXTW, nullptr},
	{ARM64_INS_IC, nullptr},
	{ARM64_INS_DC, nullptr},
	{ARM64_INS_AT, nullptr},
	{ARM64_INS_TLBI, nullptr},

	{ARM64_INS_NEGS, nullptr},
	{ARM64_INS_NGCS, nullptr},

	{ARM64_INS_ENDING, nullptr}
};

} // namespace capstone2llvmir
} // namespace retdec
