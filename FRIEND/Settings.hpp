//
//  Settings.hpp
//  Flexible Register/Instruction Extender aNd Documentation
//
//  Created by Alexander Hude on 11/11/2016.
//  Copyright © 2016 Fried Apple. All rights reserved.
//

#pragma once

#include <string>

class PluginDelegate;

class Settings
{
public:
	
	Settings() {}
	
	void		setDelegate(PluginDelegate* delegate) {m_delegate = delegate;}
	bool		show();
	
private:
	
	static int idaapi s_formCallback(int fid, form_actions_t &fa);

private:
	
	PluginDelegate* m_delegate;
	
	std::string	m_configPath;
	
	bool		m_procEnabled = false;
	bool		m_docEnabled = false;
	
};
