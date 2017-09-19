//
//  PluginDelegate.hpp
//  Flexible Register/Instruction Extender aNd Documentation
//
//  Created by Alexander Hude on 11/11/2016.
//  Copyright © 2017 Alexander Hude. All rights reserved.
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
	virtual bool			setFuncSummaryEnabled(bool enabled) = 0;
	
	virtual bool			getSettingsBlobSize(int32_t& size) = 0;
	virtual bool			loadSettingsBlob(uint8*& data, int32_t size) = 0;
	virtual bool			saveSettingsBlob(uint8*& data, int32_t size) = 0;
	virtual bool			deleteSettingsBlob() = 0;
};
