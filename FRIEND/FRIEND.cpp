//
//  FRIEND.cpp
//  Flexible Register/Instruction Extender aNd Documentation
//
//  Created by Alexander Hude on 11/11/2016.
//  Copyright © 2017 Alexander Hude. All rights reserved.
//

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>

#if (IDA_SDK_VERSION < 700) && defined(__X64__)
	#error Incompatible SDK version. Please use SDK 7.0 or higher
#elif (IDA_SDK_VERSION >= 700) && !defined(__X64__)
	#error Incompatible SDK version. Please use SDK 6.95 or lower
#endif

#if defined(USE_HEXRAYS)
	#include <hexrays.hpp>
#endif

#include "PluginDelegate.hpp"
#include "AArch64Extender.hpp"
#include "AArch32Extender.hpp"
#include "Documentation.hpp"
#include "FunctionSummary.hpp"
#include "Settings.hpp"
#include "IDAAPI.hpp"

#if defined(COMPILER_GCC) || defined(__clang__)
    #define ATTR_UNUSED __attribute__((unused))
#else
    #define ATTR_UNUSED
#endif

// The netnode helper.
// Using this node we will save current configuration information in the
// IDA database.
static const char gNodeName[] = "$ FRIEND instance";
static const uint32_t kPluginNode_Instance = 'objn';
static const uint32_t kPluginNode_Settings = 'setn';
static netnode gPluginNode(gNodeName);

#if defined(USE_HEXRAYS)
#if IDA_SDK_VERSION < 760
	// Hex-Rays API pointer
	hexdsp_t *hexdsp = nullptr;
#endif
#endif

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

// MARK: - FRIEND class

class FRIEND final : public PluginDelegate
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

		if (ph.id == PLFM_ARM)
		{
			if (ph.use64())
			{
				// AArch64 processor module extender
				m_procExtender = new AArch64Extender();
				BAIL_IF(m_procExtender == nullptr, "[FRIEND]: unable to init plugin (no memory)");
			}
			else
			{
				// ARMv7 processor module extender
				m_procExtender = new AArch32Extender();
				BAIL_IF(m_procExtender == nullptr, "[FRIEND]: unable to init plugin (no memory)");
			}
			m_procExtender->init();
		}
		
		m_funcSummary = new FunctionSummary();
		BAIL_IF(m_documentation == nullptr, "[FRIEND]: unable to init plugin (no memory)");
		
		// Hook UI notifications
		hook_to_notification_point(HT_UI, FRIEND::s_ui_hook, this);
		
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
		
		// Unhook UI notifications
		unhook_from_notification_point(HT_UI, FRIEND::s_ui_hook, this);
		
		if (m_funcSummary)
		{
			delete m_funcSummary;
			m_funcSummary = nullptr;
		}
		
		if (m_procExtender)
		{
			m_procExtender->close();
			delete m_procExtender;
			m_procExtender = nullptr;
		}
		
		if (m_documentation)
		{
			m_documentation->unregisterAction();
			delete m_documentation;
			m_documentation = nullptr;
		}
		
	#if defined(USE_HEXRAYS)
		if (m_supportsHexRays)
		{
			term_hexrays_plugin();
			m_supportsHexRays = false;
		}
	#endif
	}
	
	// MARK: Static functions

#if IDA_SDK_VERSION >= 750
	static plugmod_t *s_init(void)
#else
	static int s_init(void)
#endif
	{
		if (exist(gPluginNode) == false)
			gPluginNode.create(gNodeName);
		
		auto plugin = new FRIEND();
		if (plugin->init() == false)
			return PLUGIN_SKIP;
		
		gPluginNode.supset(kPluginNode_Instance, &plugin, sizeof(decltype(plugin)));
		
		msg("[FRIEND]: plugin loaded\n");
		return PLUGIN_KEEP;
	}
	
	static idaapi_run_ret_t s_run(idaapi_run_args_t)
	{
		FRIEND* plugin = nullptr;

		gPluginNode.supval(kPluginNode_Instance, &plugin, sizeof(decltype(plugin)));
		
		if (plugin)
			plugin->showSettings();

		idaapi_run_return(true);
	}
	
	static void s_term(void)
	{
		FRIEND* plugin = nullptr;

		gPluginNode.supval(kPluginNode_Instance, &plugin, sizeof(decltype(plugin)));
		
		if (plugin)
		{
			plugin->close();
			delete plugin;
		}

		gPluginNode.supdel(kPluginNode_Instance);
		
		msg("[FRIEND]: plugin terminated\n");
	}
	
private:
	static idaapi_hook_cb_ret_t idaapi s_idp_hook(void* user_data, int notification_code, va_list va)
	{
		return ((FRIEND*)user_data)->idpHook(notification_code, va);
	}

	static idaapi_hook_cb_ret_t idaapi s_ui_hook(void* user_data, int notification_code, va_list va)
	{
		return ((FRIEND*)user_data)->uiHook(notification_code, va);
	}

#if defined(USE_HEXRAYS)
	#if (IDA_SDK_VERSION < 710)
	static int idaapi s_hexrays_hook(void* user_data, hexrays_event_t event, va_list va)
	#else
	static ssize_t idaapi s_hexrays_hook(void* user_data, hexrays_event_t event, va_list va)
	#endif
	{
		return ((FRIEND*)user_data)->hexRaysHook(event, va);
	}
#endif
	
	// MARK: IDA Hooks
	
	idaapi_hook_cb_ret_t idpHook(int notification_code, va_list va)
	{
		if (m_procExtender == nullptr)
			return 0;
		
		if (m_procExtender->isEnabled() == false)
			return 0;
		
		switch (notification_code) {
			case processor_t::idaapi_out_instruction:
			{
				idaapi_hook_cb_ret_t ret;
			#if IDA_SDK_VERSION >= 700
				outctx_t* ctx = va_arg(va, outctx_t *);
				auto& insn = ctx->insn;
				
				class Output : public ProcOutput
				{
				public:
					Output(outctx_t* ctx) : m_ctx(ctx) {}
					
					AS_PRINTF(2, 0) void printf(const char* format, ...) override
					{
						va_list va;
						va_start(va, format);
						m_ctx->out_vprintf(format, va);
						va_end(va);
					}
					void	line(const char* line, color_t color=0) override
					{
						m_ctx->out_line(line, color);
					}
					void	flush() override
					{
						m_ctx->flush_outbuf();
					}
				private:
					outctx_t* m_ctx = nullptr;
				} procOutput(ctx);
				
				ret = 1;
			#else
				auto& insn = cmd;
				
				class Output : public ProcOutput
				{
				public:
					void	init() override
					{
						init_output_buffer(m_idaOutputBuffer, sizeof(m_idaOutputBuffer));
					}
					AS_PRINTF(2, 0) void printf(const char* format, ...) override
					{
						char tmp[kMaxElementNameLength * 2];
						va_list va;
						va_start(va, format);
						vsprintf(tmp, format, va);
						va_end(va);
						
						out_line(tmp, COLOR_DEFAULT);
					}
					void	line(const char* line, color_t color) override
					{
						out_line(line, color);
					}
					void	flush() override
					{
						term_output_buffer();
						
						gl_comm = 1;
						MakeLine(m_idaOutputBuffer);
					}
				private:
					char m_idaOutputBuffer[MAXSTR];
				} procOutput;
				
				ret = 2;
			#endif

				if (m_procExtender->output(insn.itype, insn.ea, insn.size, procOutput))
				{
					return ret;
				}
				
				break;
			}
			default:
				break;
		}
		
		return 0;
	}
	
	idaapi_hook_cb_ret_t uiHook(int notification_code, va_list va)
	{
	#if defined(USE_HEXRAYS)
		auto is_hexrays_plugin = [] (const plugin_info_t *pinfo) -> bool {
			bool is_hexrays = false;
			if ( pinfo != nullptr && pinfo->entry != nullptr )
			{
				const plugin_t *p = pinfo->entry;
				if ( streq(p->wanted_name, "Hex-Rays Decompiler") )
					is_hexrays = true;
			}
			return is_hexrays;
		};
	#endif
		
		switch (notification_code) {
		#if defined(USE_HEXRAYS)
			case ui_plugin_loaded:
			{
#if IDA_SDK_VERSION < 760
				if (hexdsp == nullptr)
				{
#endif
					if (is_hexrays_plugin(va_arg(va, plugin_info_t *)))
					{
						m_supportsHexRays = init_hexrays_plugin();
					}
#if IDA_SDK_VERSION < 760
				}
#endif
				break;
			}
			case ui_plugin_unloading:
			{
#if IDA_SDK_VERSION < 760
				if (hexdsp != nullptr)
				{
#endif
					if (is_hexrays_plugin(va_arg(va, plugin_info_t *)))
					{
						remove_hexrays_callback(FRIEND::s_hexrays_hook, this);
						term_hexrays_plugin();
						m_supportsHexRays = false;
					}
#if IDA_SDK_VERSION < 760
				}
#endif
				break;
			}
		#endif
			case ui_ready_to_run:
			{
				// IDA is fully loaded, check for HexRays support
				msg("[FRIEND]: HexRays Decompiler is %s\n", (m_supportsHexRays)? "supported" : "not supported");
				
				m_settings.load();
				
				break;
			}
			case idaapi_ui_finish_populating_form_popup:
			{
				auto form = va_arg(va, idaapi_form_t *);
				if ( IDAAPI_GetFormType(form) == BWN_DISASM )
				{
					auto popup = va_arg(va, TPopupMenu *);
				#if IDA_SDK_VERSION < 700
					auto view = get_tform_idaview(form);
					if ( view != nullptr )
				#endif
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
			#if IDA_SDK_VERSION >= 700
				qstring &hint			= *va_arg(va, qstring *);
				auto form				= va_arg(va, idaapi_form_t *);
				auto place				= va_arg(va, place_t *);
				auto important_lines	= va_arg(va, int *);
			#else
				auto form				= va_arg(va, idaapi_form_t *);
				auto place				= va_arg(va, place_t *);
				auto important_lines	= va_arg(va, int *);
				qstring &hint			= *va_arg(va, qstring *);
			#endif
				idaapi_form_type_t formType = IDAAPI_GetFormType(form);
				if (formType != BWN_DISASM)
					return 0;
				
				if ( place == nullptr )
					return 0;
			#if IDA_SDK_VERSION < 690
				auto ea = ((idaplace_t *)place)->ea;
			#else
				auto ea = place->toea();
			#endif
				
				if (IDAAPI_IsCode(IDAAPI_GetFlags(ea)) == false)
					return 0;
				
				// try to generate register/instruction hint otherwise
				int x, y;
			#if IDA_SDK_VERSION >= 700
				auto view = form;
			#else
				auto view = get_tform_idaview(form);
			#endif
				
				if (get_custom_viewer_place(view, true, &x, &y) == nullptr )
					return 0;
				
				const char* tagged_line = get_custom_viewer_curline(view, true);
				if (tagged_line == nullptr || uintptr_t(tagged_line) == -1)
					return 0;
				
				auto extractElement = [x] (const char* tagged_line, int16_t& start) -> bool {
					size_t length = qstrlen(tagged_line);
					uint16_t byte_offset = 0;
					uint16_t disp_offset = 0;
					
					// find tag closest to cursor
					while (disp_offset <= x && byte_offset < length)
					{
						char cur_char = tagged_line[byte_offset];
						if (cur_char == COLOR_ON)
						{
							start = byte_offset + 2;
							byte_offset += 2;
						}
						else if (cur_char == COLOR_OFF)
						{
							start = -1;
							byte_offset += 2;
						}
						else
						{
							disp_offset++;
							byte_offset++;
						}
					}
					
					return true;
				};
				
				// check if we have xref from current ea and summary is enabled
				xrefblk_t xb;
				if (m_funcSummary->isEnabled() && xb.first_from(ea, XREF_FAR))
				{
					// check if it is code reference
					if (IDAAPI_IsCode(IDAAPI_GetFlags(xb.to)))
					{
						// check element under cursor
						int16_t elem_start = -1;
						if (extractElement(tagged_line, elem_start))
						{
							color_t elem_type = tagged_line[elem_start - 1];
							
							// generate hint if it is address
							if (elem_type == COLOR_ADDR)
							{
								*important_lines = m_funcSummary->getSummaryHint(xb.to, hint);
								
								if (*important_lines != 0)
									return 1;
							}
						}
					}
				}
				
				// otherwise check if instruction/register hinst are enabled
				if (m_documentation->areHintsEnabled() == false)
					return 0;
				
				// generate documentation hint
				*important_lines = createHintFromDoc(tagged_line, hint, extractElement);
				
				if (*important_lines == 0)
					return 0;
				
				return 1;
			}
			default:
				break;
		}
		
		return 0;
	}

#if defined(USE_HEXRAYS)
	int hexRaysHook(hexrays_event_t event, va_list va)
	{
		switch ( event )
		{
			case hxe_maturity:
			{
				cfunc_t *cfunc = va_arg(va, cfunc_t *);
				ctree_maturity_t new_maturity = va_argi(va, ctree_maturity_t);
				if ( new_maturity == CMAT_FINAL )
				{
					struct ida_local sysreg_calls : public ctree_parentee_t
					{
					private:
						ATTR_UNUSED cfunc_t*		cfunc;
									ProcExtender*	procExtender = nullptr;
						
					public:
						sysreg_calls(cfunc_t *cf, ProcExtender* proc)
							: ctree_parentee_t(), cfunc(cf), procExtender(proc)
						{ }
						
						int idaapi visit_expr(cexpr_t *e)
						{
							if ( e->op != cot_call )
								return 0;

							if ( e->x->op != cot_helper )
								return 0;

							if (streq(e->x->helper, "ARM64_SYSREG"))
							{
								// fill helper string with system register name
								auto helper = new char[kMaxElementNameLength];
								if (procExtender->getSystemRegisterName(e->ea, helper, kMaxElementNameLength) == false)
								{
									delete[] helper;
									return 0;
								}
								
								// release cot_call expression
								e->cleanup();
								
								// create cot_helper expression
								e->replace_by(new cexpr_t(cot_helper, nullptr));
								e->helper = helper;
								e->exflags = EXFL_ALONE; // standalone helper
							}
							else if (streq(e->x->helper, "__mcr"))
							{
								// fill helper string with system register name
								auto helper = new char[kMaxElementNameLength];
								if (procExtender->getSystemRegisterName(e->ea, helper, kMaxElementNameLength) == false)
								{
									delete[] helper;
									return 0;
								}
								
								// rename '__mcr' to '_WriteSystemReg'
								delete[] e->x->helper;
								e->x->helper = new char[kMaxElementNameLength];
							#if _MSC_VER
								const char* func_name = "_WriteSystemReg";
								strncpy_s(e->x->helper, kMaxElementNameLength, func_name, strlen(func_name));
							#else
								strncpy(e->x->helper, "_WriteSystemReg", kMaxElementNameLength);
							#endif
								
								// fix args
								auto& args = *(e->a);
								auto src = new cexpr_t();
								args[2].swap(*src); // save rvalue
								
								args.clear();
								args.push_back();
								args[0].cleanup();
								args[0].replace_by(new cexpr_t(cot_helper, nullptr));
								args[0].helper = helper;
								args[0].exflags = EXFL_ALONE; // standalone helper
								
								args.push_back();
								args[1].replace_by(src); // restore rvalue
							}
							else if (streq(e->x->helper, "__mrc"))
							{
								// fill helper string with system register name
								auto helper = new char[kMaxElementNameLength];
								if (procExtender->getSystemRegisterName(e->ea, helper, kMaxElementNameLength) == false)
								{
									delete[] helper;
									return 0;
								}
								
								// rename '__mrc' to '_ReadSystemReg'
								delete[] e->x->helper;
								e->x->helper = new char[kMaxElementNameLength];
							#if _MSC_VER
								const char* func_name = "_ReadSystemReg";
								strncpy_s(e->x->helper, kMaxElementNameLength, func_name, strlen(func_name));
							#else
								strncpy(e->x->helper, "_ReadSystemReg", kMaxElementNameLength);
							#endif

								// fix args
								auto& args = *(e->a);

								args.clear();
								args.push_back();
								args[0].cleanup();
								args[0].replace_by(new cexpr_t(cot_helper, nullptr));
								args[0].helper = helper;
								args[0].exflags = EXFL_ALONE; // standalone helper
							}

							return 0;
						}
					};
					
					sysreg_calls calls(cfunc, m_procExtender);
					calls.apply_to(&cfunc->body, nullptr);
					
					cfunc->verify(FORBID_UNUSED_LABELS, true);
				}
			}
			break;
			case hxe_create_hint:
			{
				if (m_documentation->areHintsEnabled() == false)
					return 0;
				
				auto vu					= va_arg(va, vdui_t *);
				qstring &hint			= *va_arg(va, qstring *);
				auto important_lines	= va_arg(va, int *);
				
				// get ctree item under cursor (VDI_EXPR: Expression)
				auto el = vu->item.e;
				
				if (el->op == cot_empty)
					return 0;
				
				// check if we can generate function summary
				if (el->op == cot_obj || el->op == cot_call)
				{
					ea_t fea;
					if (el->op == cot_call)
						fea = el->x->obj_ea; // if cursor is on a bracket
					else
						fea = el->obj_ea; // if cursor is on function name
					
					if (m_funcSummary->isEnabled() && IDAAPI_IsCode(IDAAPI_GetFlags(fea)))
					{
						*important_lines = m_funcSummary->getSummaryHint(fea, hint);
						
						if (*important_lines != 0)
							return 1;
					}
				}
				
				// registers can only be certain element types
				if (el->op != cot_helper && el->op != cit_asm)
					return 0;
				
				// TODO: for cit_asm elements get text in __asm { ... } and implement
				//       extractElement lambda code for register under cursor
				if (el->op == cit_asm)
					return 0;
				
				// try to generate register/instruction hint otherwise
				const char* tagged_line = el->helper;
				if (tagged_line == nullptr || uintptr_t(tagged_line) == -1)
					return 0;
				
				*important_lines = createHintFromDoc(tagged_line, hint, [] (const char* tagged_line, int16_t& start) -> bool {
					// check COLOR start tag
					char cur_char = tagged_line[0];
					if (cur_char != COLOR_ON)
						return false;
					
					start = 2;
					return true;
				});
				
				if (*important_lines == 0)
					return 0;
					
				return 1;
			}
			break;
			case hxe_populating_popup:
			{
				auto form = va_arg(va, idaapi_form_t *);
				auto popup = va_arg(va, TPopupMenu *);
				
			#if IDA_SDK_VERSION < 700
				auto view = get_tform_vdui(form);
				if ( view != nullptr )
			#endif
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
				
				break;
			}
			default:
				break;
		}
		return 0;
	}
#endif
	
	template<typename F>
	int createHintFromDoc(const char* tagged_line, qstring &hint, F extractElement)
	{
		uint16_t length = qstrlen(tagged_line);
		int16_t elem_start = -1;
		int16_t elem_len = -1;
		
		if (extractElement(tagged_line, elem_start) == false)
			return 0;
		
		if (elem_start == -1)
			return 0;
		
		uint16_t byte_offset = elem_start;
		color_t elem_type = tagged_line[byte_offset - 1];
		
		// validate COLOR type tag
		if (elem_type != COLOR_INSN && elem_type != COLOR_REG && elem_type != COLOR_KEYWORD &&
			elem_type != COLOR_OPND1 && elem_type != COLOR_OPND2 && elem_type != COLOR_OPND3 &&
			elem_type != COLOR_OPND4 && elem_type != COLOR_OPND5 && elem_type != COLOR_OPND6)
			return 0;
		
		// find end of item string
		while (tagged_line[byte_offset] != COLOR_OFF && byte_offset < length)
			byte_offset++;
		elem_len = byte_offset - elem_start;
		
		if (elem_len == 0)
			return 0;
		
		char elem_str[kMaxElementNameLength]={0};
		
	#if _MSC_VER
		strncpy_s(elem_str, &tagged_line[elem_start], elem_len);
	#else
		strncpy(elem_str, &tagged_line[elem_start], elem_len);
	#endif
		
		if (elem_type == COLOR_INSN)
		{
			return m_documentation->getElementHint(ElementType::Instruction, elem_str, hint);
		}
		else // COLOR_REG, COLOR_KEYWORD, COLOR_OPNDx
		{
			return m_documentation->getElementHint(ElementType::Register, elem_str, hint);
		}
	}
	
	// MARK: PluginDelegate
	
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
		m_documentation->setHintsEnabled(enabled);
		msg("[FRIEND]: Hints %s\n", enabled ? "enabled" : "disabled");
		
		return true;
	}

	bool setProcExtenderEnabled(bool enabled) override
	{
		if (m_procExtender == nullptr)
			return false;

		if (enabled)
		{
			hook_to_notification_point(HT_IDP, FRIEND::s_idp_hook, this);
			
		#if defined(USE_HEXRAYS)
			if (m_supportsHexRays)
				install_hexrays_callback(FRIEND::s_hexrays_hook, this);
		#endif
			
			request_refresh(IWID_DISASMS);
		}
		else
		{
		#if defined(USE_HEXRAYS)
			if (m_supportsHexRays)
				remove_hexrays_callback(FRIEND::s_hexrays_hook, this);
		#endif

			unhook_from_notification_point(HT_IDP, FRIEND::s_idp_hook, this);
		}
		
		m_procExtender->setEnabled(enabled);
		msg("[FRIEND]: Processor Extender %s\n", enabled ? "enabled" : "disabled");
		
		return true;
	}
	
	bool setFuncSummaryEnabled(bool enabled) override
	{
		m_funcSummary->setEnabled(enabled);
		msg("[FRIEND]: Function Summary %s\n", enabled ? "enabled" : "disabled");
		
		return true;
	}
	
	bool getSettingsBlobSize(int32_t& size) override
	{
		size = gPluginNode.supval(kPluginNode_Settings, nullptr, 0);
		if (size > 0)
			return true;
		else
			return false;
	}
	
	bool loadSettingsBlob(uint8*& data, int32_t size) override
	{
		if (gPluginNode.supval(kPluginNode_Settings, data, size) > 0)
		{
			msg("[FRIEND]: Settings loaded from IDB\n");
			return true;
		}
		
		return false;
	}
	
	bool saveSettingsBlob(uint8*& data, int32_t size) override
	{
		gPluginNode.supdel(kPluginNode_Settings);
		if (gPluginNode.supset(kPluginNode_Settings, data, size) != 0)
		{
			msg("[FRIEND]: Settings saved to IDB\n");
			return true;
		}
		
		return false;
	}
	
	bool deleteSettingsBlob() override
	{
		gPluginNode.supdel(kPluginNode_Settings);
		return true;
	}
	
private:
	
	Settings			m_settings;
	
	Documentation*		m_documentation = nullptr;
	ProcExtender*		m_procExtender = nullptr;
	FunctionSummary*	m_funcSummary = nullptr;
	
	bool			m_supportsHexRays = false;
};

//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
#if IDA_SDK_VERSION >= 750
	plugmod_t *idaapi pluginInit(void)			{ return FRIEND::s_init();		}
#else
	int idaapi pluginInit(void)			{ return FRIEND::s_init();		}
#endif
	void idaapi pluginTerminate(void)	{ FRIEND::s_term();				}
#if IDA_SDK_VERSION >= 700
	bool idaapi pluginRun(size_t args) 	{ return FRIEND::s_run(args);	}
#else
	void idaapi pluginRun(int args) 	{ FRIEND::s_run(args);			}
#endif

plugin_t PLUGIN =
{
	IDP_INTERFACE_VERSION,
	PLUGIN_PROC | PLUGIN_DRAW,	// plugin flags
	pluginInit,					// initialize

	pluginTerminate,			// terminate. this pointer may be NULL.

	pluginRun,					// invoke plugin

	gPluginComment,				// long comment about the plugin
								// it could appear in the status line
								// or as a hint

	gPluginHelp,				// multiline help about the plugin

	gPluginWantedName,			// the preferred short name of the plugin
	gPluginWantedHotkey			// the preferred hotkey to run the plugin
};
