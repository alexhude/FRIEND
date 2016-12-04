//
//  Settings.cpp
//  Flexible Register/Instruction Extender aNd Documentation
//
//  Created by Alexander Hude on 11/11/2016.
//  Copyright © 2016 Fried Apple. All rights reserved.
//

#include <ida.hpp>
#include <idp.hpp>

#include "Settings.hpp"
#include "Documentation.hpp"
#include "ProcExtender.hpp"
#include "PluginDelegate.hpp"

enum FormActions {
	kFormAction_Init		= -1,
	kFormAction_Term		= -2,
	kFormAction_ConfigFile	=  3,
	kFormAction_HintGroups	=  4,
	kFormAction_EnableProc	=  5,
	kFormAction_EnableHints	=  6,
};

int idaapi Settings::s_formCallback(int fid, form_actions_t &fa)
{
	switch ( fid )
	{
		case kFormAction_Init:
		{
			break;
		}
		case kFormAction_Term:
		{
			break;
		}
		case kFormAction_ConfigFile:
		{
			Documentation* doc = (Documentation*)fa.get_ud();
			if (doc == nullptr)
				break;

			char configPath[MAXSTR] = {0};
			fa.get_path_value(fid, configPath, MAXSTR);
			
			std::string path(configPath);
			if (doc->loadConfigFile(path))
			{
				fa.refresh_field(kFormAction_HintGroups);
			}
			break;
		}
		case kFormAction_HintGroups:
		{
			break;
		}
		case kFormAction_EnableProc:
		{
			break;
		}
		case kFormAction_EnableHints:
		{
			break;
		}
		default:
			break;
	}
	
	return 1;
}

bool Settings::show()
{
	Documentation* doc = nullptr;
	ProcExtender* proc = nullptr;
	
	if (m_delegate)
	{
		doc = m_delegate->getDocumentation();
		proc = m_delegate->getProcExtender();
	}
	
	char configPath[MAXSTR] = {0};

	static const char form[] =
	"STARTITEM 0\n"
	"FRIEND Settings\n\n"
	"%/%*"
	"              Flexible Register/Instruction Extender aNd Documentation\n"
	"<XML Config\\::f3:0:43::>"
	"\n"
	"<:E4::55::>\n\n"
	"<Enable Processor Extender:C5>\n"
	"<Enable Hints:C6>>\n"
	"\n";
	
	static const int widths[] = { 55 };
	
	// set config file
	qstrncpy(configPath, m_configPath.c_str(), MAXSTR);
	
	// set hint group chooser
	chooser_info_t group_chooser;
	group_chooser.flags = CH_NOIDB | CH_MULTI;
	group_chooser.icon = -1;
	group_chooser.columns = 1;
	group_chooser.widths = widths;
	group_chooser.obj = doc;
	group_chooser.sizer = [] (void *obj) -> uint32 {
		Documentation* doc = (Documentation*)obj;
		if (doc == nullptr)
			return 0;
		
		return doc->getGroupCount();
	};
	group_chooser.getl = [] (void *obj, uint32 n, char *const *arrptr) {
		if ( n == 0 ) // generate the column headers
		{
			qstrncpy(arrptr[0], "Element groups", MAXSTR);
			return;
		}
		
		Documentation* doc = (Documentation*)obj;
		if (doc == nullptr)
		{
			arrptr[0][0] = 0;
			return;
		}
		
		qsnprintf(arrptr[0], MAXSTR, "%s", doc->getGroupName(n-1));
	};
	
	intvec_t group_select;
	
	//
	if (doc && doc->getGroupCount() != 0)
	{
		for (uint32_t i = 0; i < doc->getGroupCount(); i++)
		{
			if (doc->isGroupEnabled(i)) {
				group_select.push_back(i + 1);
			}
		}
	}

	ushort checkboxMask = 0;
	checkboxMask |= (m_procEnabled)? 0x1 : 0;
	checkboxMask |= (m_docEnabled)? 0x2 : 0;
	
	if ( AskUsingForm_c(form,
						s_formCallback, doc,
						configPath,
						&group_chooser, &group_select,
						&checkboxMask) > 0 )
	{
		if (doc)
		{
			doc->disableAllGroups();
			for (int index : group_select)
			{
				doc->setGroupEnabled(index-1);
			}
		}
		
		bool procEnabled = checkboxMask & 0x1;
		bool docEnabled = checkboxMask & 0x2;
		
		if (m_delegate)
		{
			if (docEnabled != m_docEnabled)
				m_delegate->setHintsEnabled(docEnabled);
			
			if (procEnabled != m_procEnabled)
				m_delegate->setProcExtenderEnabled(procEnabled);
		}
		m_docEnabled = docEnabled;
		m_procEnabled = procEnabled;
		
		m_configPath = std::string(configPath);
		
		return true;
	}
	
	return false;
}
