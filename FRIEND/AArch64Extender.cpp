//
//  AArch64Extender.cpp
//  Flexible Register/Instruction Extender aNd Documentation
//
//  Created by Alexander Hude on 11/11/2016.
//  Copyright © 2017 Alexander Hude. All rights reserved.
//

#include <regex>

#include <idp.hpp>
#include <allins.hpp>

#include "AArch64Extender.hpp"
#include "IDAAPI.hpp"

#ifdef __EA64__
	#define PRINTF_ADDR	"%llX"
#else
	#define PRINTF_ADDR	"%X"
#endif

#define BAIL_IF(cond, ...)		\
	do							\
	{							\
		if ((cond))				\
		{						\
			msg(__VA_ARGS__);	\
			goto bail;			\
		}						\
	}							\
	while (0)

#define RegisterInfo(optype, itype, reg) ((optype << 24) | (itype << 20) | reg)

bool AArch64Extender::init()
{
	if (cs_open(CS_ARCH_ARM64, CS_MODE_ARM, &m_capstoneHandle) != CS_ERR_OK)
	{
		msg("[FRIEND]: failed to initialize capstone\n");
		return false;
	}
	
	cs_option(m_capstoneHandle, CS_OPT_DETAIL, CS_OPT_ON);
	
	return true;
}

bool AArch64Extender::close()
{
	if (m_capstoneHandle != 0)
	{
		if (cs_close(&m_capstoneHandle) != CS_ERR_OK)
			return false;
	}
	
	return true;
}

bool AArch64Extender::output(uint16_t itype, ea_t address, uint32_t size, ProcOutput& procOutput)
{
	switch (itype)
	{
		case ARM_msr:
		case ARM_mrs:
		case ARM_sys:
			return printCapstoneOutput(address, size, procOutput);
		default:
			break;
	}
	return false;
}

bool AArch64Extender::getSystemRegisterName(ea_t address, char* nameBuffer, uint32_t nameLength)
{
	bool ret = false;
	
	cs_insn *capstoneDisasm;
	cs_insn ci;
	uint32_t rawInstruction = 0;
	size_t count = 0;
	
	cs_arm64_op* ops = nullptr;
	uint32_t sysRegIdx = -1;
	arm64_op_type type = ARM64_OP_INVALID;
	uint8_t insn_type = 0;
	
	const char* tmp = nullptr;
	
	BAIL_IF(IDAAPI_GetBytes(&rawInstruction, sizeof(rawInstruction), address) == 0, "[FRIEND]: unable to read instruction at " PRINTF_ADDR "\n", address);
	
	count = cs_disasm(m_capstoneHandle, (const uint8_t*)&rawInstruction, sizeof(rawInstruction), address, 1, &capstoneDisasm);
	BAIL_IF(count <= 0, "[FRIEND]: unable to decode instruction at " PRINTF_ADDR " [ %.4X ]\n", address, rawInstruction);
	
	ci = capstoneDisasm[0];
	
	BAIL_IF(ci.id != ARM64_INS_MRS && ci.id != ARM64_INS_MSR, "[FRIEND]: unsupported instruction at " PRINTF_ADDR " [ %.4X ]\n", address, rawInstruction);
	BAIL_IF(ci.detail == nullptr, "[FRIEND]: unable to get details for instruction at " PRINTF_ADDR " [ %.4X ]\n", address, rawInstruction);
	
	ops = ci.detail->arm64.operands;
	
	sysRegIdx = (ci.id == ARM64_INS_MSR)? 0 : 1;
	type = ops[sysRegIdx].type;
	insn_type = 0;
	
	tmp = cs_reg_name(m_capstoneHandle, RegisterInfo(type, insn_type, ops[sysRegIdx].reg));
	BAIL_IF(tmp == nullptr, "[FRIEND]: unable to get register name for instruction at " PRINTF_ADDR " [ %.4X ]\n", address, rawInstruction);
	
	qstrncat(nameBuffer, SCOLOR_ON, nameLength);
	qstrncat(nameBuffer, SCOLOR_REG, nameLength);
	qstrncat(nameBuffer, tmp, nameLength);
	qstrncat(nameBuffer, SCOLOR_OFF, nameLength);
	qstrncat(nameBuffer, SCOLOR_REG, nameLength);
	
	qstrupr(nameBuffer);
	
	ret = true;
	
bail:

	if (count > 0)
		cs_free(capstoneDisasm, 1);
	
	return ret;
}

bool AArch64Extender::isEnabled()
{
	return m_enabled;
}

bool AArch64Extender::setEnabled(bool enabled)
{
	m_enabled = enabled;
	return true;
}

bool AArch64Extender::printCapstoneOutput(ea_t address, uint32_t size, ProcOutput& procOutput)
{
	bool ret = false;
	
	cs_insn *capstoneDisasm;
	cs_insn ci;
	uint8_t rawInstruction[4] = {0};
	std::string mnemonic;
	size_t count = 0;
	
	BAIL_IF(IDAAPI_GetBytes(rawInstruction, size, address) == 0, "[FRIEND]: unable to read instruction at " PRINTF_ADDR "\n", address);

	count = cs_disasm(m_capstoneHandle, rawInstruction, size, address, 1, &capstoneDisasm);
	BAIL_IF(count <= 0, "[FRIEND]: unable to decode instruction at " PRINTF_ADDR " [ %.2X%.2X%.2X%.2X ]\n", address,
			rawInstruction[0], rawInstruction[1], rawInstruction[2], rawInstruction[3]);
	
	ci = capstoneDisasm[0];
	
	procOutput.init();
	
	mnemonic = (SCOLOR_ON SCOLOR_INSN + std::string(qstrupr(ci.mnemonic)) + SCOLOR_OFF SCOLOR_INSN);
	
	procOutput.printf("%-20s", mnemonic.c_str());
	
	if (ci.detail)
	{
		std::string operands(qstrupr(ci.op_str));
		
		uint8_t op_count = ci.detail->arm64.op_count;
		cs_arm64_op* ops = ci.detail->arm64.operands;
		for (int i=0; i < op_count; i++)
		{
			arm64_op_type type = ops[i].type;
			uint8_t insn_type = 0;
			
			switch (ci.id)
			{
				case ARM64_INS_AT:		insn_type = 1; break;
				case ARM64_INS_DC:		insn_type = 2; break;
				case ARM64_INS_IC:		insn_type = 3; break;
				case ARM64_INS_TLBI:	insn_type = 4; break;
				case ARM64_INS_ISB:		insn_type = 1; break;
				case ARM64_INS_DMB:		insn_type = 2; break;
				case ARM64_INS_DSB:		insn_type = 3; break;
				default:
					break;
			}
			
			const char* tmp = cs_reg_name(m_capstoneHandle, RegisterInfo(type, insn_type, ops[i].reg));
			if (tmp)
			{
				char regName[kMaxElementNameLength] = {0};
				
				qstrncpy(regName, tmp, sizeof(regName));
				std::string reg(qstrupr(regName));
				
				operands = std::regex_replace(operands, std::regex(reg), SCOLOR_ON SCOLOR_REG + reg + SCOLOR_OFF SCOLOR_REG);
			}
		}
		
		procOutput.line(operands.c_str(), COLOR_UNAME);
	}
	else
	{
		if(qstrstr(ci.op_str, "0x") != nullptr)
			procOutput.line(ci.op_str, COLOR_REG);
		else
			procOutput.line(qstrupr(ci.op_str), COLOR_REG);
	}

	procOutput.flush();
	
	ret = true;
	
bail:
	
	if (count > 0)
		cs_free(capstoneDisasm, 1);
	
	return ret;
}
