//
//  AArch32Extender.hpp
//  Flexible Register/Instruction Extender aNd Documentation
//
//  Created by Alexander Hude on 12/09/2017.
//  Copyright © 2017 Alexander Hude. All rights reserved.
//

#pragma once

#include <map>
#include "capstone.h"

#include "ProcExtender.hpp"

class AArch32Extender : public ProcExtender
{
public:
	
	AArch32Extender() {};
	~AArch32Extender() {};
	
	bool	init() override;
	bool	close() override;
	
	bool	output(uint16_t itype, ea_t address, uint32_t size, ProcOutput& procOutput) override;
	
	bool	getSystemRegisterName(ea_t address, char* nameBuffer, uint32_t nameLength) override;
	
private:
	
	bool	isEnabled() override;
	bool	setEnabled(bool enabled) override;

	bool	isThumbArea(ea_t address);
	bool	printMoveOutput(ea_t address, uint32_t size, ProcOutput& procOutput);
	
private:
	
	static 	std::map<uint32_t, const char*> s_operandMap;
	
	csh		m_capstoneHandle = 0;
	cs_mode m_modeARM = cs_mode(0);
	cs_mode m_modeThumb = cs_mode(0);
};
