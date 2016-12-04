//
//  Documentation.cpp
//  Flexible Register/Instruction Extender aNd Documentation
//
//  Created by Alexander Hude on 11/11/2016.
//  Copyright © 2016 Fried Apple. All rights reserved.
//

#include "loader.hpp"
#include "Documentation.hpp"
#include <string>
#include <sstream>
#include <regex>

#define COL_STDSTR(str, tag) SCOLOR_ON tag << str << SCOLOR_OFF tag

bool Documentation::loadConfigFile(std::string filePath)
{
	m_xmlDoc.reset();
	m_groups.clear();
	
	auto result = m_xmlDoc.load_file(filePath.c_str());
	if (! result)
		return false;

	m_queryVars.add("doc_id", pugi::xpath_type_string);
	m_queryVars.add("group_idx", pugi::xpath_type_number);
	m_queryVars.add("token_id", pugi::xpath_type_string);
	m_getDocQuery = pugi::xpath_query("/documentation/document[@id = string($doc_id)]/path", &m_queryVars);
	m_getTokenQuery = pugi::xpath_query("/documentation/elements/group[$group_idx]/hint[@token = string($token_id)]", &m_queryVars);

	//	auto node = m_xmlDoc.child("references");
	//	size_t n = std::distance(node.children("token").begin(), node.children("token").end());
	//	size_t n = node.select_nodes( "token" ).size();
	
	try
	{
		auto elementsNode = m_xmlDoc.child("documentation").child("elements");

		uint32_t index = 1;
		for (pugi::xml_node groupNode: elementsNode.children("group"))
		{
			Group group;
			
			group.enable = false;
			
			std::string type = groupNode.attribute("type").value();
			if (type == "reg")
				group.type = ElementType::Register;
			else if (type == "ins")
				group.type = ElementType::Instruction;
			else
				group.type = ElementType::Unknown;
			
			group.name = groupNode.attribute("name").value();
			group.index = index;
			
			m_groups.push_back(group);
			
			index++;
		}
	}
	catch (const pugi::xpath_exception& e)
	{
		msg("[FRIEND]: unable to load configuration (%s)\n", e.what());
		return false;
	}

	msg("[FRIEND]: configuration xml loaded from %s\n", filePath.c_str());
	
	return true;
}

bool Documentation::registerAction()
{
	m_actionDesc = ACTION_DESC_LITERAL(
		m_actionName,		// action name
		m_popupTitle,		// action title
		this,				// handler
		nullptr,			// shortcut
		nullptr,			// tooltip
		-1);				// icon

	return register_action(m_actionDesc);
}

bool Documentation::unregisterAction()
{
	return unregister_action(m_actionName);
}

bool Documentation::areHintsEnabled()
{
	return m_hintsEnabled;
}

void Documentation::setHintsEnabled(bool enabled)
{
	m_hintsEnabled = enabled;
}

bool Documentation::availableForIdentifier()
{
	if (m_xmlDoc.empty())
		return false;
	
	char identifier[128] = {0};
	
	bool res = get_highlighted_identifier(identifier, sizeof(identifier), 0);

	if (!res)
		return res;
	
	bool found = false;
	for (Group& group : m_groups)
	{
		if (group.enable == false)
			continue;
		
		m_queryVars.set("token_id", identifier);
		m_queryVars.set("group_idx", double(group.index));
		
		try
		{
			auto token_xnode = m_getTokenQuery.evaluate_node(m_xmlDoc);
			if (token_xnode.node().empty())
				continue;
			
			m_identifierNode = token_xnode.node();
			found = true;
			break;
		}
		catch (const pugi::xpath_exception& e)
		{
			msg("[FRIEND]: unable to find token (%s)\n", e.what());
		}
	}
	
	return found;
}

const char* Documentation::getActionName() const
{
	return m_actionName;
}

const char* Documentation::getActionMenuTitle() const
{
	return m_popupTitle;
}

uint32_t Documentation::getGroupCount()
{
	return m_groups.size();
}

const char* Documentation::getGroupName(uint32_t index)
{
	if (index >= m_groups.size())
		return nullptr;
	
	return m_groups[index].name.c_str();
}

bool Documentation::isGroupEnabled(uint32_t index)
{
	if (index < m_groups.size())
		return m_groups[index].enable;
	
	return false;
}

bool Documentation::setGroupEnabled(uint32_t index)
{
	if (index < m_groups.size())
	{
		m_groups[index].enable = true;
		return true;
	}
	
	return false;
}

void Documentation::disableAllGroups()
{
	for (Group& group : m_groups)
	{
		group.enable = false;
	}
}

std::string	Documentation::getElementHint(ElementType type, char* element, int* lines)
{
	auto unescapeString = [] (std::string input) -> std::string {
		std::string output;
		
		output = std::regex_replace(input, std::regex("&quot;"), "\"");
		output = std::regex_replace(output, std::regex("&amp;"), "&");
		output = std::regex_replace(output, std::regex("&apos;"), "'");
		output = std::regex_replace(output, std::regex("&lt;"), "<");
		output = std::regex_replace(output, std::regex("&gt;"), ">");

		return output;
	};
	
	*lines = 0;
	pugi::xml_node elementNode;

	bool found = false;
	for (Group group : m_groups)
	{
		if (group.enable == false)
			continue;
		
		if (group.type == ElementType::Unknown)
			continue;
		
		if (group.type != type)
			continue;
	
		m_queryVars.set("token_id", element);
		m_queryVars.set("group_idx", double(group.index));
		
		try
		{
			auto token_xnode = m_getTokenQuery.evaluate_node(m_xmlDoc);
			if (token_xnode.node().empty())
				continue;
			
			elementNode = token_xnode.node();
			found = true;
			break;
		}
		catch (const pugi::xpath_exception& e)
		{
			msg("[FRIEND]: unable to find token (%s)\n", e.what());
		}
	}
	
	if (found == false)
		return "";

	std::ostringstream hint_text;

	// get header attribute
	std::string header = elementNode.attribute("header").value();
	if (header[0] != '\0')
	{
		// add header line to hint
		hint_text << " " << COL_STDSTR(unescapeString(header), SCOLOR_LOCNAME) << " ";
		(*lines)++;
	}
//	else
//	{
//		msg("[FRIEND]: unable to find attribute 'header' for \"%s\"\n", element);
//	}

	// get info attribute
	std::string info = unescapeString(elementNode.child_value());
	if (info[0] != '\0')
	{
		if (*lines != 0)
		{
			hint_text << "\n ";
			(*lines)++;
		}
		
		// replace line breaks
		//info = std::regex_replace(info, std::regex("\\\\n"), "\n");
		
		std::stringstream desc(info);
		std::string token;
		
		// add info lines to hint
		while (std::getline(desc, token))
		{
			if (*lines != 0)
				hint_text << "\n ";
			hint_text << COL_STDSTR(token, SCOLOR_AUTOCMT) << " ";
			(*lines)++;
		}
	}
//	else
//	{
//		msg("[FRIEND]: unable to find attribute 'info' for \"%s\"\n", element);
//	}
	
	return hint_text.str();
}

//

bool Documentation::getReferenceDetails(ReferenceDetails& details)
{
	auto doc_id = m_identifierNode.attribute("doc_id").value();
	if (doc_id[0] == '\0') {
		msg("[FRIEND]: unable to find attribute 'doc_id' for \"%s\"\n", m_identifierNode.attribute("token").value());
		return false;
	}
	
	details.doc_id = doc_id;
	
	auto pageAttr = m_identifierNode.attribute("page");
	if (pageAttr.value()[0] == '\0') {
		msg("[FRIEND]: unable to find attribute 'page' for \"%s\"\n", m_identifierNode.attribute("token").value());
		return false;
	}
	
	details.page = pageAttr.as_int();
	
	return true;
}

bool Documentation::openInBrowser(ReferenceDetails& details)
{
	m_queryVars.set("doc_id", details.doc_id.c_str());

	auto doc_xnode = m_getDocQuery.evaluate_node(m_xmlDoc);
	auto node = doc_xnode.node();
	if (node.empty())
	{
		msg("[FRIEND]: unable to find document %s\n", details.doc_id.c_str());
		return false;
	}

	std::string docpath = node.child_value();
	
	std::stringstream sstream;
	
	sstream << "osascript -e '" <<
	"tell application \"Google Chrome\"\n" <<
	"	set URL of active tab of window 1 to \"file://" << docpath << "?#page=" << details.page << "\"\n" <<
	"	delay 1\n" <<
	"	reload active tab of window 1\n" <<
	"end tell\n" <<
	"'";
	
	// open pdf page in separate thread
	auto ascript = sstream.str();
	m_scriptThread = std::thread([ascript] () {
		system(ascript.c_str());
	});
	m_scriptThread.detach();
	
	return true;
}

// MARK:: action_handler_t methods

int idaapi Documentation::activate(action_activation_ctx_t *)
{
	ReferenceDetails details;
	
	bool res = getReferenceDetails(details);
	if (! res)
		return 0;
	
	openInBrowser(details);
	
	return 0;
}

action_state_t idaapi Documentation::update(action_update_ctx_t *)
{
	return AST_ENABLE_ALWAYS;
}
