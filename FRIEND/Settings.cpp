//
//  Settings.cpp
//  Flexible Register/Instruction Extender aNd Documentation
//
//  Created by Alexander Hude on 11/11/2016.
//  Copyright © 2017 Alexander Hude. All rights reserved.
//

#include <ida.hpp>
#include <idp.hpp>

#include "Settings.hpp"
#include "Documentation.hpp"
#include "ProcExtender.hpp"
#include "PluginDelegate.hpp"
#include "IDAAPI.hpp"

enum FormActions {
	kFormAction_Init			= -1,
	kFormAction_Term			= -2,
	kFormAction_ConfigFile		=  3,
	kFormAction_HintGroups		=  4,
	kFormAction_EnableProc		=  5,
	kFormAction_EnableHints		=  6,
	kFormAction_EnableSummary	=  7,
	kFormAction_SaveSettings	=  8,
};

const ushort kCheckBoxMask_ProcEnable		= (0b0001);
const ushort kCheckBoxMask_DocEnable		= (0b0010);
const ushort kCheckBoxMask_SummaryEnable	= (0b0100);
const ushort kCheckBoxMask_SaveSettings		= (0b1000);

// Settings serialization

typedef enum : uint32_t {
	kItemTag_ConfigFile,
	kItemTag_HintGroups,
	kItemTag_EnableProc,
	kItemTag_EnableHints,
	kItemTag_EnableSummary,
	kItemTag_Terminator,
} ItemTag;

struct Element
{
	uint32_t	size;
	ItemTag		tag;
};

struct BlobHeader : Element {
	uint32_t version;
};

struct ItemHeader : Element {
	uint32_t 	num;
};

struct ItemBool : ItemHeader {
	uint32_t	value;
};

const uint32_t kSettingsBlobVersion 	= 0x0100;
const ItemTag kSettingsBlobHeaderTag 	= ItemTag('frnd');

///

#if IDA_SDK_VERSION >= 700

struct group_chooser_t : public chooser_multi_t
{
public:
	group_chooser_t(Documentation* doc)
		: chooser_multi_t(CH_KEEP, 1, kWidths, kHeaders), m_doc(doc)
	{height = 10;}
	
	~group_chooser_t()
	{}
	
	size_t idaapi get_count() const override
	{
		if (m_doc == nullptr)
			return 0;
		
		return m_doc->getGroupCount();
	}

	void idaapi get_row(qstrvec_t *cols,
						int *icon_,
						chooser_item_attrs_t *attrs,
						size_t n) const override
	{
		qstrvec_t &cols_array = *cols;

		if (m_doc == nullptr)
		{
			cols_array[0][0] = '\0';
			return;
		}

		cols_array[0].sprnt("%s", m_doc->getGroupName(n));
	}
	
private:
	
	const int kWidths[1] = { 45 };
	const char* kHeaders[1] = { "Element groups" };
	
	Documentation* m_doc = nullptr;
};


#endif

///

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
			
			if (path != "")
				doc->loadConfigFile(path);
			else
				doc->resetConfigFile();
			
			fa.refresh_field(kFormAction_HintGroups);
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
		case kFormAction_EnableSummary:
		{
			break;
		}
		case kFormAction_SaveSettings:
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
	"<Enable Hints:C6>\n"
	"<Enable Function Summary:C7>\n"
	"<Save Settings in IDB:C8>>\n"
	"\n";

	// set config file
	qstrncpy(configPath, m_configPath.c_str(), MAXSTR);
	
	// set hint group chooser
#if IDA_SDK_VERSION >= 700
	group_chooser_t group_chooser(doc);
#else
	static const int widths[] = { 55 };
	
	chooser_info_t group_chooser;
	memset(&group_chooser, 0, sizeof(chooser_info_t));
	group_chooser.cb = sizeof(chooser_info_t);
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
#endif
	
	idaapi_chooser_sel_t group_select;
	
	//
	if (doc && doc->getGroupCount() != 0)
	{
		for (uint32_t i = 0; i < doc->getGroupCount(); i++)
		{
			if (doc->isGroupEnabled(i)) {
				group_select.push_back(idaapi_chooser_sel_base + i);
			}
		}
	}

	ushort checkboxMask = 0;
	checkboxMask |= (m_procEnabled)? kCheckBoxMask_ProcEnable : 0;
	checkboxMask |= (m_docEnabled)? kCheckBoxMask_DocEnable : 0;
	checkboxMask |= (m_summaryEnabled)? kCheckBoxMask_SummaryEnable : 0;
	checkboxMask |= (m_saveSettings)? kCheckBoxMask_SaveSettings : 0;
	
	if ( IDAAPI_AskForm(form,
						s_formCallback, doc,
						configPath,
						&group_chooser, &group_select,
						&checkboxMask) > 0 )
	{
		if (doc)
		{
			doc->disableAllGroups();
			for (auto index : group_select)
			{
				doc->setGroupEnabled(index - idaapi_chooser_sel_base);
			}
		}
		
		bool procEnabled = checkboxMask & kCheckBoxMask_ProcEnable;
		bool docEnabled = checkboxMask & kCheckBoxMask_DocEnable;
		bool summaryEnabled = checkboxMask & kCheckBoxMask_SummaryEnable;
		bool saveSettings = checkboxMask & kCheckBoxMask_SaveSettings;
		
		if (m_delegate)
		{
			if (docEnabled != m_docEnabled)
				m_delegate->setHintsEnabled(docEnabled);
			
			if (procEnabled != m_procEnabled)
				m_delegate->setProcExtenderEnabled(procEnabled);
			
			if (summaryEnabled != m_summaryEnabled)
				m_delegate->setFuncSummaryEnabled(summaryEnabled);
			
			if ((saveSettings != m_saveSettings) && (saveSettings == false))
				m_delegate->deleteSettingsBlob();
		}

		m_docEnabled = docEnabled;
		m_procEnabled = procEnabled;
		m_summaryEnabled = summaryEnabled;
		m_saveSettings = saveSettings;

		m_configPath = std::string(configPath);
		
		if (m_delegate && m_saveSettings)
		{
			// serialize settings
			int32_t blobSize = 0;
			blobSize += sizeof(BlobHeader);												// blob header
			blobSize += sizeof(ItemHeader) + m_configPath.size() + 1;					// config file path + '\0'
			blobSize += sizeof(ItemHeader) + (group_select.size() * sizeof(uint32_t));	// selected hint groups
			blobSize += sizeof(ItemBool);												// processor extentsion flag
			blobSize += sizeof(ItemBool);												// hints flag
			blobSize += sizeof(ItemBool);												// function summary flag
			blobSize += sizeof(ItemHeader);												// terminator
			
			uint8_t* blob = new uint8_t[blobSize];
			memset(blob, 0, blobSize);
			
			uint8_t* blob_ptr = blob;
			
			// Blob header
			BlobHeader* blob_hdr = (BlobHeader*)blob_ptr;
			blob_hdr->size = sizeof(BlobHeader);
			blob_hdr->tag = kSettingsBlobHeaderTag;
			blob_hdr->version = kSettingsBlobVersion;
			blob_ptr += blob_hdr->size;
			
			// config file path
			ItemHeader* item_config = (ItemHeader*)blob_ptr;
			item_config->size = sizeof(ItemHeader) + m_configPath.size() + 1;
			item_config->tag = kItemTag_ConfigFile;
			item_config->num = 1;
			memcpy(blob_ptr + sizeof(ItemHeader), m_configPath.c_str(), m_configPath.size());
			blob_ptr += item_config->size;
			
			// selected hint groups
			ItemHeader* item_hints = (ItemHeader*)blob_ptr;
			item_hints->size = sizeof(ItemHeader) + (group_select.size() * sizeof(uint32_t));
			item_hints->tag = kItemTag_HintGroups;
			item_hints->num = group_select.size();
			uint32_t* group_ptr = (uint32_t*)(blob_ptr + sizeof(ItemHeader));
			for (auto index : group_select)
			{
				*group_ptr = index - idaapi_chooser_sel_base;
				group_ptr++;
			}
			blob_ptr += item_hints->size;
			
			// processor extension flag
			ItemBool* item_procflag = (ItemBool*)blob_ptr;
			item_procflag->size = sizeof(ItemBool);
			item_procflag->tag = kItemTag_EnableProc;
			item_procflag->num = 1;
			item_procflag->value = m_procEnabled? 1 : 0;
			blob_ptr += item_procflag->size;

			// hints flag
			ItemBool* item_hintflag = (ItemBool*)blob_ptr;
			item_hintflag->size = sizeof(ItemBool);
			item_hintflag->tag = kItemTag_EnableHints;
			item_hintflag->num = 1;
			item_hintflag->value = m_docEnabled? 1 : 0;
			blob_ptr += item_hintflag->size;

			// function summary flag
			ItemBool* item_summflag = (ItemBool*)blob_ptr;
			item_summflag->size = sizeof(ItemBool);
			item_summflag->tag = kItemTag_EnableSummary;
			item_summflag->num = 1;
			item_summflag->value = m_summaryEnabled? 1 : 0;
			blob_ptr += item_summflag->size;

			// terminator
			ItemHeader* terminator = (ItemHeader*)blob_ptr;
			terminator->size = sizeof(ItemHeader);
			terminator->tag = kItemTag_Terminator;
			blob_ptr += terminator->size;
			
			m_delegate->saveSettingsBlob(blob, blobSize);
			
			delete[] blob;
		}
		
		return true;
	}
	
	return false;
}

void Settings::load()
{
	if (m_delegate == nullptr)
		return;
	
	int32_t size;
	if (m_delegate->getSettingsBlobSize(size) == false)
		return;
	
	uint8_t* blob = new uint8_t[size];

	m_delegate->loadSettingsBlob(blob, size);

	// unzerialize settings
	
	Documentation* doc = m_delegate->getDocumentation();
	
	if (((BlobHeader*)blob)->tag != kSettingsBlobHeaderTag) {
		delete[] blob;
		return;
	}
	
	uint8_t* blob_ptr = blob;
	while (blob_ptr < (blob + size))
	{
		Element* e = (Element*)blob_ptr;
		
		if (e->tag == kItemTag_Terminator)
			break;
		
		switch (e->tag)
		{
			case kItemTag_ConfigFile:
			{
				m_configPath = std::string((char*)(blob_ptr + sizeof(ItemHeader)));
				doc->loadConfigFile(m_configPath);
				break;
			}
			case kItemTag_HintGroups:
			{
				if (doc->getGroupCount() == 0)
					break;
				
				ItemHeader* item_hints = (ItemHeader*)e;
				uint32_t* group_ptr = (uint32_t*)(blob_ptr + sizeof(ItemHeader));
				doc->disableAllGroups();

				while (item_hints->num)
				{
					doc->setGroupEnabled(*group_ptr);
					item_hints->num--;
					group_ptr++;
				}
				break;
			}
			case kItemTag_EnableProc:
			{
				ItemBool* item_procflag = (ItemBool*)blob_ptr;

				m_procEnabled = (item_procflag->value != 0)? true : false;
				m_delegate->setProcExtenderEnabled(m_procEnabled);
				
				break;
			}
			case kItemTag_EnableHints:
			{
				ItemBool* item_hintflag = (ItemBool*)blob_ptr;
				
				m_docEnabled = (item_hintflag->value != 0)? true : false;
				m_delegate->setHintsEnabled(m_docEnabled);

				break;
			}
			case kItemTag_EnableSummary:
			{
				ItemBool* item_summflag = (ItemBool*)blob_ptr;

				m_summaryEnabled = (item_summflag->value != 0)? true : false;
				m_delegate->setFuncSummaryEnabled(m_summaryEnabled);

				break;
			}
			default:
				break;
		}
		
		blob_ptr += e->size;
	}
	
	delete[] blob;
	
	m_saveSettings = true;
}
