//
//  Documentation.hpp
//  Flexible Register/Instruction Extender aNd Documentation
//
//  Created by Alexander Hude on 11/11/2016.
//  Copyright © 2016 Fried Apple. All rights reserved.
//

#pragma once

#include <ida.hpp>
#include <idp.hpp>
#include <vector>
#include <thread>

#include "pugixml/pugixml.hpp"

enum class ElementType
{
	Register,
	Instruction,
	Unknown,
};

class Documentation : public action_handler_t
{
public:
	
	Documentation() {}
	
	bool			loadConfigFile(std::string filePath);
	
	bool			registerAction();
	bool			unregisterAction();
	
	bool			areHintsEnabled();
	void			setHintsEnabled(bool enabled);
	bool			availableForIdentifier();

	const char*		getActionName() const;
	const char*		getActionMenuTitle() const;
	
	uint32_t		getGroupCount();
	const char*		getGroupName(uint32_t index);
	bool			isGroupEnabled(uint32_t index);
	bool			setGroupEnabled(uint32_t index);
	void			disableAllGroups();
	
	std::string		getElementHint(ElementType type, char* element, int* lines);
	
private:
	
	struct ReferenceDetails
	{
		std::string	doc_id;
		uint32_t	page;
	};
	
	bool			getReferenceDetails(ReferenceDetails& details);
	
	bool			openInBrowser(ReferenceDetails& details);
	
private:
	
	virtual int idaapi activate(action_activation_ctx_t *);
	virtual action_state_t idaapi update(action_update_ctx_t *);
	
private:
	
	bool						m_hintsEnabled = false;
	
	action_desc_t				m_actionDesc;
	
	const char*					m_actionName = "FRIEND::Documentation::Show";
	const char*					m_popupTitle = "Show Documentation";
	
	pugi::xml_document			m_xmlDoc;
	pugi::xpath_variable_set	m_queryVars;
	pugi::xpath_query			m_getDocQuery;
	pugi::xpath_query			m_getTokenQuery;
	pugi::xml_node				m_identifierNode;
	
	struct Group
	{
		bool		enable;
		ElementType type;
		std::string name;
		uint32_t	index;
	};
	
	std::vector<Group>			m_groups;
	
	std::thread					m_scriptThread;
};
