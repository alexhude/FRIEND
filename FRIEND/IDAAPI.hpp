//
//  IDAAPI.hpp
//  Flexible Register/Instruction Extender aNd Documentation
//
//  Created by Alexander Hude on 16/09/2017.
//  Copyright © 2017 Alexander Hude. All rights reserved.
//

#pragma once

#if IDA_SDK_VERSION >= 700

	#define idaapi_form_t							TWidget
	#define idaapi_form_type_t						twidget_type_t

	#define idaapi_chooser_sel_base					0
	#define idaapi_chooser_sel_t					sizevec_t
	#define idaapi_hook_cb_ret_t					ssize_t
	#define idaapi_run_args_t						size_t
	#define idaapi_run_ret_t						bool
	#define idaapi_run_return(x)					return (x)

	#define IDAAPI_IsBE()							(inf.is_be())
	#define IDAAPI_AskForm							ask_form
	#define IDAAPI_GetFlags							get_flags
	#define IDAAPI_GetFuncName						get_func_name
	#define IDAAPI_IsString							is_strlit
	#define IDAAPI_IsCode							is_code
	#define IDAAPI_STRTYPE_C						STRTYPE_C
	#define IDAAPI_GetStringContent					get_strlit_contents
	#define IDAAPI_GetMaxStringLength				get_max_strlit_length
	#define IDAAPI_GetFormType						get_widget_type
	#define IDAAPI_GetBytes(buf, size, ea)			get_bytes((buf), (size), (ea))
	#define IDAAPI_GetSegmentReg					get_sreg

	#define idaapi_ui_finish_populating_form_popup	ui_finish_populating_widget_popup
	#define idaapi_out_instruction					ev_out_insn

#else

	#define idaapi_form_t							TForm
	#define idaapi_form_type_t						tform_type_t

	#define idaapi_chooser_sel_base					1
	#define idaapi_chooser_sel_t					intvec_t
	#define idaapi_hook_cb_ret_t					int
	#define idaapi_run_args_t						int
	#define idaapi_run_ret_t						void
	#define idaapi_run_return(x)

	#define IDAAPI_IsBE()							(inf.mf == true)
	#define IDAAPI_AskForm							AskUsingForm_c
	#define IDAAPI_GetFlags							getFlags
	#define IDAAPI_GetFuncName						get_func_name2
	#define IDAAPI_IsString							isASCII
	#define IDAAPI_IsCode							isCode
	#define IDAAPI_STRTYPE_C						ASCSTR_C
	#define IDAAPI_GetStringContent					get_ascii_contents2
	#define IDAAPI_GetMaxStringLength				get_max_ascii_length
	#define IDAAPI_GetFormType						get_tform_type
	#define IDAAPI_GetBytes(buf, size, ea)			get_many_bytes((ea), (buf), (size))
	#define IDAAPI_GetSegmentReg					get_segreg

	#define idaapi_ui_finish_populating_form_popup	ui_finish_populating_tform_popup
	#define idaapi_out_instruction					custom_out

#endif
