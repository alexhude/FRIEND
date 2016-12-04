//
//  FRIEND.cpp
//  Flexible Register/Instruction Extender aNd Documentation
//
//  Created by Alexander Hude on 11/11/2016.
//  Copyright © 2016 Fried Apple. All rights reserved.
//

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>

#include "PluginDelegate.hpp"
#include "AArch64Extender.hpp"
#include "Documentation.hpp"
#include "Settings.hpp"

// The netnode helper.
// Using this node we will save current configuration information in the
// IDA database.
static netnode gPluginNode;
static const char gNodeName[] = "$ FRIEND instance";
static const uint32_t kPluginNode_Instance = 0;

char gPluginHelp[] = "FRIEND";
char gPluginComment[] = "This module improves disassembly and embeds register/instruction documentation to IDA.";
char gPluginWantedName[] = "FRIEND";
char gPluginWantedHotkey[] = "";

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

class FRIEND : public PluginDelegate
{
public:
	FRIEND() {}
	~FRIEND() {}
	
	bool init()
	{
		m_settings.setDelegate(this);
		
		m_documentation = new Documentation();
		BAIL_IF(m_documentation == nullptr, "[FRIEND]: unable to init plugin (no memory)");

		m_documentation->registerAction();

		// AArch64 processor module extender
		if (ph.id == PLFM_ARM && ph.use64())
		{
			m_procExtender = new AArch64Extender();
			BAIL_IF(m_documentation == nullptr, "[FRIEND]: unable to init plugin (no memory)");

			m_procExtender->init();
		}
		
		return true;
		
	bail:
		
		return false;
	}
	
	void showSettings()
	{
		m_settings.show();
	}
	
	void close()
	{
		setProcExtenderEnabled(false);
		setHintsEnabled(false);
		
		if (m_procExtender)
		{
			m_procExtender->close();
			delete m_procExtender;
		}
		
		if (m_documentation)
		{
			m_documentation->unregisterAction();
			delete m_documentation;
		}
	}
	
	static int s_init(void)
	{
		gPluginNode.create(gNodeName);
		
		auto plugin = new FRIEND();
		plugin->init();
		
		gPluginNode.altset(kPluginNode_Instance, (nodeidx_t)plugin);
		
		return PLUGIN_KEEP;
	}
	
	static void s_run(int)
	{
		auto plugin = (FRIEND*)gPluginNode.altval(kPluginNode_Instance);
		
		if (plugin)
			plugin->showSettings();
	}
	
	static void s_term(void)
	{
		auto plugin = (FRIEND*)gPluginNode.altval(kPluginNode_Instance);
		
		if (plugin)
		{
			plugin->close();
			delete plugin;
		}

		gPluginNode.altdel(kPluginNode_Instance);
		
		gPluginNode.kill();
	}
	
private:
	static int idaapi s_idp_hook(void* user_data, int notification_code, va_list va)
	{
		return ((FRIEND*)user_data)->idpHook(notification_code, va);
	}

	static int idaapi s_ui_hook(void* user_data, int notification_code, va_list va)
	{
		return ((FRIEND*)user_data)->uiHook(notification_code, va);
	}
	
	int idpHook(int notification_code, va_list va)
	{
		if (m_procExtender == nullptr)
			return 0;
		
		if (m_procExtender->isEnabled() == false)
			return 0;
		
		switch (notification_code) {
			case processor_t::custom_out:
			{
				if (m_procExtender->output(cmd.ea, cmd.size))
				{
					return 2;
				}
				
				break;
			}
			default:
				break;
		}
		
		return 0;
	}
	
	int uiHook(int notification_code, va_list va)
	{
		if (m_documentation == nullptr)
			return 0;
		
		switch (notification_code) {
			case ui_finish_populating_tform_popup:
			{
				auto form = va_arg(va, TForm *);
				if ( get_tform_type(form) == BWN_DISASM )
				{
					auto popup = va_arg(va, TPopupMenu *);
					auto view = get_tform_idaview(form);
					if ( view != nullptr )
					{
						bool addSeparator = false;
						
						if (m_documentation->availableForIdentifier())
						{
							if (! addSeparator)
							{
								attach_action_to_popup(form, popup, "-");
								addSeparator = true;
							}
							
							attach_action_to_popup(form, popup, m_documentation->getActionName());
						}
					}
				}
				
				break;
			}
			case ui_get_custom_viewer_hint:
			{
				if (m_documentation->areHintsEnabled() == false)
					return 0;
				
				auto form				= va_arg(va, TForm *);
				auto place				= va_arg(va, place_t *);
				auto important_lines	= va_arg(va, int *);
				qstring &hint				= *va_arg(va, qstring *);
				
				if (get_tform_type(form) != BWN_DISASM)
					return 0;
				
				if ( place == nullptr )
					return 0;
				
				auto ea = place->toea();
				
				if (isCode(getFlags(ea)) == false)
					return 0;
				
				int x, y;
				auto view = get_tform_idaview(form);
				
				if (get_custom_viewer_place(view, true, &x, &y) == nullptr )
					return 0;
				
				//static char clean_line[256] = {0};
				const char* tagged_line = get_custom_viewer_curline(view, true);
				
				uint16_t length = qstrlen(tagged_line);
				uint16_t disp_offset = 0;
				uint16_t byte_offset = 0;
				int16_t elem_start = -1;
				int16_t elem_len = -1;
				color_t elem_type = COLOR_DEFAULT;
				while (disp_offset <= x && byte_offset < length)
				{
					char cur_char = tagged_line[byte_offset];
					if (cur_char == COLOR_ON)
					{
						elem_type = tagged_line[byte_offset+1];
						
						elem_start = byte_offset + 2;
						byte_offset += 2;
					}
					else if (cur_char == COLOR_OFF)
					{
						elem_type = COLOR_DEFAULT;
						
						elem_start = -1;
						byte_offset += 2;
					}
					else
					{
						disp_offset++;
						byte_offset++;
					}
				}
				
				if (elem_type != COLOR_INSN && elem_type != COLOR_REG && elem_type != COLOR_KEYWORD &&
					elem_type != COLOR_OPND1 && elem_type != COLOR_OPND2 && elem_type != COLOR_OPND3 &&
					elem_type != COLOR_OPND4 && elem_type != COLOR_OPND5 && elem_type != COLOR_OPND6)
					return 0;
				
				while (tagged_line[byte_offset] != COLOR_OFF && byte_offset < length)
					byte_offset++;
				elem_len = byte_offset - elem_start;
				
				if (elem_len == 0)
					return 0;
				
				char elem_str[16]={0};
				strncpy(elem_str, &tagged_line[elem_start], elem_len);
				
				if (elem_type == COLOR_INSN)
				{
					std::string inst_hint = m_documentation->getElementHint(ElementType::Instruction, elem_str, important_lines);
					if (*important_lines == 0)
						return 0;
					
					hint = inst_hint.c_str();
					return 1;
				}
				else // COLOR_REG, COLOR_KEYWORD, COLOR_OPNDx
				{
					std::string reg_hint = m_documentation->getElementHint(ElementType::Register, elem_str, important_lines);
					if (*important_lines == 0)
						return 0;
					
					hint = reg_hint.c_str();
					return 1;
				}
			}
			default:
				break;
		}
		
		return 0;
	}
	
	//MARK: PluginDelegate
	
	Documentation* getDocumentation() override
	{
		return m_documentation;
	}
	
	ProcExtender* getProcExtender() override
	{
		return m_procExtender;
	}
	
	bool setHintsEnabled(bool enabled) override
	{
		if (m_documentation == nullptr)
			return false;
		
		if (enabled)
			hook_to_notification_point(HT_UI, FRIEND::s_ui_hook, this);
		else
			unhook_from_notification_point(HT_UI, FRIEND::s_ui_hook, this);
		
		m_documentation->setHintsEnabled(enabled);
		msg("[FRIEND]: Hints %s\n", enabled ? "enabled" : "disabled");
		
		return true;
	}

	bool setProcExtenderEnabled(bool enabled) override
	{
		if (m_procExtender == nullptr)
			return false;

		if (enabled)
			hook_to_notification_point(HT_IDP, FRIEND::s_idp_hook, this);
		else
			unhook_from_notification_point(HT_IDP, FRIEND::s_idp_hook, this);
		
		m_procExtender->setEnabled(enabled);
		msg("[FRIEND]: Processor Extender %s\n", enabled ? "enabled" : "disabled");
		
		return true;
	}
	
private:
	
	Settings		m_settings;
	
	Documentation*	m_documentation = nullptr;
	ProcExtender*	m_procExtender = nullptr;
};

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	PLUGIN_PROC|PLUGIN_DRAW,	// plugin flags
	FRIEND::s_init,				// initialize

	FRIEND::s_term,				// terminate. this pointer may be NULL.

	FRIEND::s_run,				// invoke plugin

	gPluginComment,				// long comment about the plugin
								// it could appear in the status line
								// or as a hint

	gPluginHelp,				// multiline help about the plugin

	gPluginWantedName,			// the preferred short name of the plugin
	gPluginWantedHotkey			// the preferred hotkey to run the plugin
};
