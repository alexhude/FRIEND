//
//  AArch64Extender.hpp
//  Flexible Register/Instruction Extender aNd Documentation
//
//  Created by Alexander Hude on 11/11/2016.
//  Copyright © 2016 Fried Apple. All rights reserved.
//

#pragma once

#include "capstone.h"

#include "ProcExtender.hpp"

class AArch64Extender : public ProcExtender
{
public:
	
	AArch64Extender() {};
	~AArch64Extender() {};
	
	bool	init() override;
	bool	close() override;
	
	bool	output(ea_t address, uint32_t size) override;
	
private:
	
	bool isEnabled() override;
	bool setEnabled(bool enabled) override;
	
	// update instructions
	
	bool printCapstoneOutput(ea_t address);
	
private:
	
	char					m_idaOutputBuffer[MAXSTR];
	
	csh						m_capstoneHandle = 0;
};
