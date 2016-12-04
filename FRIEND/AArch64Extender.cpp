//
//  AArch64Extender.cpp
//  Flexible Register/Instruction Extender aNd Documentation
//
//  Created by Alexander Hude on 11/11/2016.
//  Copyright © 2016 Fried Apple. All rights reserved.
//

#include <idp.hpp>
#include <allins.hpp>
#include <regex>

#include "AArch64Extender.hpp"

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

bool AArch64Extender::output(ea_t address, uint32_t size)
{
	switch (cmd.itype)
	{
		case ARM_msr:
			return printCapstoneOutput(address);

		case ARM_mrs:
			return printCapstoneOutput(address);
			
		case ARM_sys:
			return printCapstoneOutput(address);
			
		default:
			break;
	}
	
	return false;
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

// MARK: update instructions

bool AArch64Extender::printCapstoneOutput(ea_t address)
{
	cs_insn *capstoneInstruction;
	uint32_t rawInstruction;
	
	BAIL_IF(get_many_bytes(address, &rawInstruction, sizeof(rawInstruction)) == 0, "[FRIEND]: Unable to read instruction\n");

	init_output_buffer(m_idaOutputBuffer, sizeof(m_idaOutputBuffer));

	if (cs_disasm(m_capstoneHandle, (const uint8_t*)&rawInstruction, sizeof(rawInstruction), address, 1, &capstoneInstruction) > 0)
	{
		std::string mnemonic(SCOLOR_ON SCOLOR_INSN + std::string(qstrupr(capstoneInstruction[0].mnemonic)) + SCOLOR_OFF SCOLOR_INSN);
		
		out_snprintf("%-20s", mnemonic.c_str());
		
		if (capstoneInstruction[0].detail)
		{
			std::string operands(qstrupr(capstoneInstruction[0].op_str));
			
			uint8_t op_count = capstoneInstruction[0].detail->arm64.op_count;
			cs_arm64_op* ops = capstoneInstruction[0].detail->arm64.operands;
			for (int i=0; i < op_count; i++)
			{
				arm64_op_type type = ops[i].type;
				uint8_t insn_type = 0;
				#define RegisterInfo(optype, itype, reg) ((optype << 24) | (itype << 20) | reg)
				
				switch (capstoneInstruction->id)
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
					char regName[32];
					strcpy(regName, tmp);
					std::string reg(qstrupr(regName));
					
					operands = std::regex_replace(operands, std::regex(reg), SCOLOR_ON SCOLOR_REG + reg + SCOLOR_OFF SCOLOR_REG);
				}
			}
			
			out_line(operands.c_str(), COLOR_UNAME);
		}
		else
		{
			out_line(qstrupr(capstoneInstruction[0].op_str), COLOR_REG);
		}
	}
	else
	{
		OutBadInstruction();
	}
	cs_free(capstoneInstruction, 1);
	
	term_output_buffer();
	
	gl_comm = 1;
	MakeLine(m_idaOutputBuffer);
	
	return true;
	
bail:
	
	return false;
}
