//
//  FunctionSummary.hpp
//  Flexible Register/Instruction Extender aNd Documentation
//
//  Created by Alexander Hude on 11/7/17.
//  Copyright © 2017 Alexander Hude. All rights reserved.
//

#pragma once

#include <pro.h>

class FunctionSummary
{
public:
	FunctionSummary() {};
	~FunctionSummary() {};
	
	bool 	isEnabled();
	bool	setEnabled(bool enabled);
	int		getSummaryHint(ea_t address, qstring &hint);
	
private:
	
	bool	m_enabled = false;
	
};
