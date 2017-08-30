//
//  FunctionSummary.cpp
//  Flexible Register/Instruction Extender aNd Documentation
//
//  Created by Alexander Hude on 11/7/17.
//  Copyright © 2017 Alexander Hude. All rights reserved.
//


#include <sstream>

#include <idp.hpp>
#include <funcs.hpp>

#include "FunctionSummary.hpp"

#define COL_STDSTR(str, tag) SCOLOR_ON tag << str << SCOLOR_OFF tag

bool 	FunctionSummary::isEnabled()
{
	return m_enabled;
}

bool	FunctionSummary::setEnabled(bool enabled)
{
	m_enabled = enabled;
	return true;
}

int	FunctionSummary::getSummaryHint(ea_t address, qstring &hint)
{
	int out_lines = 0;
	
	func_t* pfn = get_func(address);
	if (pfn == nullptr)
		return 0;
	
	uint32_t callCnt = 0;
	uint32_t strCnt = 0;
	func_item_iterator_t fii;
	ea_t fea;
	qstring tmp;
	
	struct RefInfo {
		ea_t		address;
		qstring		string;
		uint32_t	count;
	};
	
	qlist<RefInfo> flist;
	qlist<RefInfo> slist;
	
	for (bool ok = fii.set(pfn, address); ok; ok = fii.next_addr() )
	{
		fea = fii.current();
		if(is_call_insn(fea))
		{
			auto ref = get_first_fcref_from(fea);
			if (ref != BADADDR)
			{
				RefInfo item;
				item.count = 1;
				item.address = ref;
				get_func_name2(&item.string, item.address);
				
				if (callCnt != 0 && flist.back().address == item.address)
					flist.back().count++;
				else
					flist.push_back(item);
				
				callCnt++;
			}
		}
		else
		{
			auto ref = get_first_dref_from(fea);
			if (ref != BADADDR)
			{
				// some strings are nested two levels; they point to an offset just outside the function
				// and then this offset points to the real string
				auto ref2 = get_first_dref_from(ref);
				if (!isASCII(getFlags(ref)) && ref2 != BADADDR)
					ref = ref2;

				if (isASCII(getFlags(ref)))
				{
					RefInfo item;
					item.count = 1;
					item.address = ref;
					
					char ctmp[256];
					get_ascii_contents2(ref, get_max_ascii_length(ref, ASCSTR_C), ASCSTR_C, ctmp, 256);
					item.string = ctmp;
					
					item.string.replace("\n", "\\n");
					
					if (strCnt != 0 && slist.back().address == ref)
						slist.back().count++;
					else
						slist.push_back(item);
					
					strCnt++;
				}
			}
		}
		
	}
	
	get_func_name2(&tmp, address);
	
	std::ostringstream sum_hint;
	sum_hint << " " << tmp.c_str() << COL_STDSTR(": ", SCOLOR_AUTOCMT) <<
	COL_STDSTR(callCnt, SCOLOR_CREFTAIL) << COL_STDSTR(" calls, ", SCOLOR_AUTOCMT) <<
	COL_STDSTR(strCnt, SCOLOR_CREFTAIL) << COL_STDSTR(" strings \n", SCOLOR_AUTOCMT);
	out_lines = 1;
	
	bool pad = false;
	if (flist.size())
	{
		sum_hint << "\n " << COL_STDSTR("Calls:\n", SCOLOR_MACRO);
		out_lines += 2;
		
		while (! flist.empty())
		{
			auto item = flist.front();
			sum_hint << COL_STDSTR("  - ", SCOLOR_AUTOCMT) << COL_STDSTR(item.string.c_str(), SCOLOR_CNAME);
			if (item.count != 1)
				sum_hint << COL_STDSTR(" x", SCOLOR_CREFTAIL) << COL_STDSTR(item.count, SCOLOR_CREFTAIL) << " \n";
			else
				sum_hint << " \n";
			
			flist.pop_front();
			out_lines++;
		}
		
		pad = true;
	}
	
	if (slist.size())
	{
		sum_hint << "\n " << COL_STDSTR("Strings:\n", SCOLOR_MACRO);
		out_lines += 2;
		
		while (! slist.empty())
		{
			auto item = slist.front();
			sum_hint << COL_STDSTR("  - ", SCOLOR_AUTOCMT) << COL_STDSTR(item.string.c_str(), SCOLOR_DSTR);
			if (item.count != 1)
				sum_hint << COL_STDSTR(" x", SCOLOR_CREFTAIL) << COL_STDSTR(item.count, SCOLOR_CREFTAIL) << " \n";
			else
				sum_hint << " \n";
			
			slist.pop_front();
			out_lines++;
		}
		
		pad = true;
	}
	
	if (pad)
	{
		sum_hint << "\n";
		out_lines++;
	}
	
	hint = sum_hint.str().c_str();
	return out_lines;
}
