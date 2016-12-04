//
//  PluginDelegate.h
//  Flexible Register/Instruction Extender aNd Documentation
//
//  Created by Alexander Hude on 11/11/2016.
//  Copyright © 2016 Fried Apple. All rights reserved.
//

#pragma once

class Documentation;
class ProcExtender;

class PluginDelegate
{
public:
	virtual Documentation*	getDocumentation() = 0;
	virtual ProcExtender*	getProcExtender() = 0;
	
	virtual bool			setHintsEnabled(bool enabled) = 0;
	virtual bool			setProcExtenderEnabled(bool enabled) = 0;
};
