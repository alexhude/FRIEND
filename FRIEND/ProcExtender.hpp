//
//  ProcExtender.h
//  Flexible Register/Instruction Extender aNd Documentation
//
//  Created by Alexander Hude on 11/11/2016.
//  Copyright © 2017 Alexander Hude. All rights reserved.
//

#pragma once

#include <pro.h>

static const uint32_t kMaxElementNameLength	= 32;

class ProcOutput
{
public:
	virtual void	init() {};
	virtual void	printf(const char* format, ...) {};
	virtual void	line(const char* line, color_t color=0) {};
	virtual void	flush() {};
};

class ProcExtender
{
public:
	virtual ~ProcExtender() {}
	
	virtual bool	init() = 0;
	virtual bool	close() = 0;

	virtual bool	isEnabled() = 0;
	virtual bool	setEnabled(bool enabled) = 0;

	virtual bool	output(uint16_t itype, ea_t address, uint32_t size, ProcOutput& procOutput) = 0;
	virtual bool	getSystemRegisterName(ea_t address, char* nameBuffer, uint32_t nameLength) = 0;
	
protected:
	bool			m_enabled = false;
	
};
