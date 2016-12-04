//
//  ViewController.swift
//  HintEditor
//
//  Created by Alexander Hude on 10/11/2016.
//  Copyright © 2016 Fried Apple. All rights reserved.
//

import Cocoa
import AEXML

// MARK: String escaping/unescaping

extension String
{
	func escapeEntities() -> String
	{
		return CFXMLCreateStringByEscapingEntities(nil, self as CFString, nil) as String
	}
	
	func unescapeEntities() -> String
	{
		return CFXMLCreateStringByUnescapingEntities(nil, self as CFString, nil) as String
	}
}

// MARK: InfoTextView class

class InfoTextView : NSTextView
{
	// replace TAB with spaces
	override func doCommand(by selector: Selector) {
		if selector == #selector(NSResponder.insertTab(_:))
		{
			let TAB = String(repeating: " ", count: 4)
			self.insertText(TAB, replacementRange: NSMakeRange(self.string!.characters.count, self.string!.characters.count))
		}
		else
		{
			super.doCommand(by: selector)
		}
	}
}

// MARK: PreviewTextField class

@IBDesignable
class PreviewTextView : NSTextView
{
	@IBInspectable override var backgroundColor: NSColor {
		didSet {
			layer?.backgroundColor = backgroundColor.cgColor
		}
	}
	
	@IBInspectable var hintHeaderColor: NSColor?
	
	@IBInspectable var hintInfoColor: NSColor?
	
#if TARGET_INTERFACE_BUILDER
	override func prepareForInterfaceBuilder()
	{
		self.string = ""
		var preview : String
		var attribute : NSMutableAttributedString
		
		// Generate header
		preview = " Instruction Header"
		attribute = NSMutableAttributedString.init(string: preview)
		let headerRange = (preview as NSString).range(of: preview)
		let boldFont = NSFontManager.shared().convert(self.font!, toHaveTrait: .boldFontMask)
		attribute.addAttribute(NSForegroundColorAttributeName, value: self.hintHeaderColor!, range: headerRange)
		attribute.addAttribute(NSFontAttributeName, value: boldFont, range: headerRange)
			
		self.textStorage?.append(attribute)
		
		preview = ""

		preview += " \n\n"
		
		let infoString =	" This is a placeholder for instruction description\n" +
							" Instuction operands:\n" +
							" - operand 1\n" +
							" - operand 2\n" +
							" - operand 3"
		preview += infoString
			
		attribute = NSMutableAttributedString.init(string: preview)
		let infoRange = (preview as NSString).range(of: preview)
		let unboldFont = NSFontManager.shared().convert(self.font!, toHaveTrait: .unboldFontMask)
		attribute.addAttribute(NSForegroundColorAttributeName, value: self.hintInfoColor!, range: infoRange)
		attribute.addAttribute(NSFontAttributeName, value: unboldFont, range: infoRange)
			
		self.textStorage?.append(attribute)
	}
#endif
}

// MARK: ViewController class

class ViewController: NSViewController
{
	class Hint
	{
		let token: String
		
		init(_ token: String)
		{
			self.token = token
		}
	}
	
	class Group
	{
		let name: String
		
		var hints: [Hint]!
		
		init(_ name: String)
		{
			self.name = name
			self.hints = []
		}
	}
	
	var elements : [Group] = []
	var elementsFiltered : [Group] = []
	var filterString: String = ""
	
	var xmlPath : String?
	var xmlDoc : AEXMLDocument?
	
	var filteredGroupIndex : Int? = nil
	var filteredHintIndex : Int? = nil
	var elementChanged = false
	
	@IBOutlet weak var elementsView: NSOutlineView!
	
	@IBOutlet weak var tokenField: NSTextField!
	@IBOutlet weak var docField: NSTextField!
	@IBOutlet weak var pageField: NSTextField!
	@IBOutlet weak var headerField: NSTextField!
	@IBOutlet var infoField: InfoTextView!
	@IBOutlet var previewField: PreviewTextView!
	
	@IBOutlet weak var saveButton: NSButton!
	@IBOutlet weak var addButton: NSButton!
	@IBOutlet weak var deleteButton: NSButton!
	
	@IBOutlet weak var searchField: NSSearchField!
	// MARK: local methods
	
	func readHint(groupIndex: Int, hintIndex: Int)
	{
		let element = xmlDoc?.root["elements"]["group"].all![groupIndex]["hint"].all![hintIndex]
		
		if let id = element?.attributes["token"]
		{
			tokenField.stringValue = id
		}
		
		if let doc = element?.attributes["doc_id"]
		{
			docField.stringValue = doc
		}
		
		if let page = element?.attributes["page"]
		{
			pageField.stringValue = page
		}
		
		if let header = element?.attributes["header"]
		{
			headerField.stringValue = header.unescapeEntities()
		}
		
		if let info = element?.value
		{
			infoField.string = info
		}
		
		generatePreview()
		
		elementChanged = false
		
		updateButtonStates()
	}
	
	func clearFields()
	{
		for field in [ tokenField, docField, pageField, headerField ]
		{
			field?.stringValue = ""
		}
		
		for field in [ infoField, previewField ]
		{
			field?.string = ""
		}
	}

	
	func generatePreview()
	{
		guard filteredGroupIndex != nil else {
			return
		}
		
		previewField.string = ""
		
		if headerField.stringValue != ""
		{
			let preview = " " + headerField.stringValue
			
			let attribute = NSMutableAttributedString.init(string: preview)
			let headerRange = (preview as NSString).range(of: preview)
			let boldFont = NSFontManager.shared().convert(previewField.font!, toHaveTrait: .boldFontMask)
			attribute.addAttribute(NSForegroundColorAttributeName, value: previewField.hintHeaderColor!, range: headerRange)
			attribute.addAttribute(NSFontAttributeName, value: boldFont, range: headerRange)
			
			previewField.textStorage?.append(attribute)
		}
		
		if infoField.string != ""
		{
			var preview = ""
			
			if headerField.stringValue != ""
			{
				preview += " \n\n"
			}
			
			let kUnicode_LineSeparator = 0x2028
			let infoString = infoField.string?.replacingOccurrences(of: String(describing: UnicodeScalar(kUnicode_LineSeparator)!), with: "\n ")
				.replacingOccurrences(of: "\n", with: "\n ")
				.replacingOccurrences(of: "\r", with: "\n ")
			preview += " " + infoString!
			
			let attribute = NSMutableAttributedString.init(string: preview)
			let infoRange = (preview as NSString).range(of: preview)
			let unboldFont = NSFontManager.shared().convert(previewField.font!, toHaveTrait: .unboldFontMask)
			attribute.addAttribute(NSForegroundColorAttributeName, value: previewField.hintInfoColor!, range: infoRange)
			attribute.addAttribute(NSFontAttributeName, value: unboldFont, range: infoRange)
			
			previewField.textStorage?.append(attribute)
		}
	}
	
	func filterHints(for string: String)
	{
		filteredGroupIndex = nil
		filteredHintIndex = nil
		
		elementsFiltered.removeAll()
		for group in elements
		{
			let newGroup = Group(group.name)

			newGroup.hints = group.hints.filter {
				string == "" || $0.token.localizedCaseInsensitiveContains(string)
			}
			
			if newGroup.hints.count > 0
			{
				elementsFiltered.append(newGroup)
			}
		}
		
		filterString = string
		
		elementsView.reloadData()
	}
	
	func updateButtonStates()
	{
		guard filteredGroupIndex != nil else {
			
			// allow nothing
			saveButton.isEnabled = false
			addButton.isEnabled = false
			deleteButton.isEnabled = false
			
			return
		}
		
		let tokenEmpty = tokenField.stringValue.isEmpty
		
		if filteredHintIndex != nil
		{
			let tokenModified = tokenField.stringValue != elementsFiltered[filteredGroupIndex!].hints[filteredHintIndex!].token
			
			if tokenModified == true
			{
				if tokenEmpty == false
				{
					// allow to add element with token
					addButton.isEnabled = true
					
					saveButton.isEnabled = false
					deleteButton.isEnabled = false
				}
				else
				{
					// allow nothing
					saveButton.isEnabled = false
					addButton.isEnabled = false
					deleteButton.isEnabled = false
				}
			}
			else
			{
				// allow to save and delete element
				if elementChanged == false
				{
					saveButton.isEnabled = false
				}
				else
				{
					saveButton.isEnabled = true
				}
				deleteButton.isEnabled = true

				addButton.isEnabled = false
			}
			
			elementChanged = true
		}
		else
		{
			// group selected
			if tokenEmpty == false
			{
				// allow to add element with token
				addButton.isEnabled = true

				saveButton.isEnabled = false
				deleteButton.isEnabled = false
			}
			else
			{
				// allow nothing
				saveButton.isEnabled = false
				addButton.isEnabled = false
				deleteButton.isEnabled = false
			}
		}
	}
	
	// MARK: NSViewController initialization
	
	override func viewDidLoad() {
		super.viewDidLoad()
		
		// Do any additional setup after loading the view.
	
		infoField.placeholderString = "info"
		previewField.placeholderString = "preview"
		
		for textView in [ infoField, previewField ]
		{
			textView?.textContainer!.widthTracksTextView    =   false
			textView?.textContainer!.heightTracksTextView	=	false
			textView?.textContainer!.containerSize          =   CGSize(width: CGFloat.greatestFiniteMagnitude, height: CGFloat.greatestFiniteMagnitude)
		}
		
		let attributes = [NSFontAttributeName: tokenField.font as Any]
		infoField.typingAttributes = attributes
		previewField.typingAttributes = attributes
		
		elementsView.sizeLastColumnToFit();
		
		updateButtonStates()
		
		DispatchQueue.main.async {
			self.tokenField.becomeFirstResponder()
		}
	}
	
	override var representedObject: Any? {
		didSet {
			// Update the view, if already loaded.
		}
	}

	// MARK: File menu handlers
	
	override var acceptsFirstResponder: Bool { return true }
	
	@IBAction func openDocument(_ sender: Any)
	{
		let fileDialog: NSOpenPanel = NSOpenPanel()
		fileDialog.allowsMultipleSelection = false
		fileDialog.allowsOtherFileTypes = false
		fileDialog.canChooseDirectories = false
		fileDialog.allowedFileTypes = ["xml"]
		fileDialog.runModal()
		
		guard
			let path = fileDialog.url?.path,
			let data = try? Data(contentsOf: URL(fileURLWithPath: path))
			else {
				return
		}

		clearFields()
		elements.removeAll()
		elementsFiltered.removeAll()
		filteredGroupIndex = nil
		filteredHintIndex = nil
		
		updateButtonStates()
		
		do
		{
			xmlDoc = try AEXMLDocument(xml: data)
			xmlPath = path

			guard let groups = xmlDoc?.root["elements"]["group"].all else {
				throw AEXMLError.elementNotFound
			}
			
			for group in groups
			{
				guard let name = group.attributes["name"] else {
					continue
				}
				
				let newGroup = Group(name)
				
				guard let hints = group["hint"].all else {
					throw AEXMLError.elementNotFound
				}
				
				for token in hints
				{
					guard let id = token.attributes["token"] else {
						continue
					}
					
					newGroup.hints.append(Hint(id))
				}
				
				elements.append(newGroup)
			}
			
			filterHints(for: "")
		}
		catch
		{
			print("HintEditor: Unable to open XML file: \(error)")
		}

		elementsView.reloadData()
	}
	
	@IBAction func saveDocument(_ sender: Any)
	{
		guard xmlDoc != nil && xmlPath != nil else {
			return
		}

		do
		{
			try xmlDoc?.xml.write(to: URL(fileURLWithPath: xmlPath!), atomically: false, encoding: String.Encoding.utf8)
		}
		catch
		{
			print("HintEditor: Unable to write XML file: \(error)")
		}
	}
	
	@IBAction func performClose(_ sender: Any)
	{
		guard xmlDoc != nil else {
			return
		}
		
		clearFields()
		
		xmlPath = nil
		xmlDoc = nil
		
		elements.removeAll()
		elementsFiltered.removeAll()
		filteredGroupIndex = nil
		filteredHintIndex = nil
		
		updateButtonStates()
		
		elementsView.reloadData()
	}
	
	// MARK: Hint button handlers
	
	@IBAction func saveHint(_ sender: Any)
	{
		if tokenField.stringValue == elementsFiltered[filteredGroupIndex!].hints[filteredHintIndex!].token
		{
			// token is same, update element
			guard
				let realGroupIdx = elements.index(where: {$0.name == elementsFiltered[filteredGroupIndex!].name}),
				let realHintIdx = elements[realGroupIdx].hints.index(where: {$0.token == tokenField.stringValue})
			else
			{
				return
			}

			guard let element = xmlDoc?.root["elements"]["group"].all![realGroupIdx]["hint"].all![realHintIdx] else {
				addHint(sender)
				return
			}
			
			element.attributes["token"] = tokenField.stringValue
			element.attributes["doc_id"] = docField.stringValue
			element.attributes["page"] = pageField.stringValue
			element.attributes["header"] = headerField.stringValue
			
			let kUnicode_LineSeparator = 0x2028
			element.value = infoField.string?.replacingOccurrences(of: String(describing: UnicodeScalar(kUnicode_LineSeparator)!), with: "\n")
				.replacingOccurrences(of: "\r", with: "\n")
			
			elementChanged = false
			saveButton.isEnabled = false
		}
		else
		{
			// token has changed, create new element
			addHint(sender)
		}
	}
	
	@IBAction func addHint(_ sender: Any)
	{
		guard filteredGroupIndex != nil else {
			return
		}

		guard
			let realGroupIdx = elements.index(where: {$0.name == elementsFiltered[filteredGroupIndex!].name}),
			let group = xmlDoc?.root["elements"]["group"].all![realGroupIdx]
		else
		{
			return
		}
		
		if group["hint"].all(withAttributes: ["token" : tokenField.stringValue]) != nil
		{
			print("HintEditor: Hint with id=\"\(tokenField.stringValue)\" already exists!")
			return
		}
		
		let attributes = [
			"token":	tokenField.stringValue,
			"doc_id":	docField.stringValue,
			"page":		pageField.stringValue,
			"header":	headerField.stringValue
		]
		
		// fix line breaks
		let kUnicode_LineSeparator = 0x2028
		let infoString = infoField.string?.replacingOccurrences(of: String(describing: UnicodeScalar(kUnicode_LineSeparator)!), with: "\n")
			.replacingOccurrences(of: "\r", with: "\n")
		
		let newHint = Hint(tokenField.stringValue)
		var filteredHint : Hint?
		
		if filteredHintIndex == nil
		{
			// insert first
			group.addChild(name: "hint", value: infoString, attributes:attributes, at:0)
			
			elements[realGroupIdx].hints!.insert(newHint, at:0)
			
			// check if new token matches search filter
			if searchField.stringValue.isEmpty == true ||
				tokenField.stringValue.localizedCaseInsensitiveContains(searchField.stringValue)
			{
				filteredHint = Hint(tokenField.stringValue)
				filteredHintIndex = 0
			}
		}
		else
		{
			let selectedHintToken = elementsFiltered[filteredGroupIndex!].hints[filteredHintIndex!].token
			guard let realHintIdx = elements[realGroupIdx].hints.index(where: {$0.token == selectedHintToken}) else {
				return
			}
			
			// insert after currentHintIndex
			group.addChild(name: "hint", value: infoString, attributes:attributes, at:realHintIdx + 1)
			
			elements[realGroupIdx].hints!.insert(newHint, at:realHintIdx + 1)

			// check if new token matches search filter
			if searchField.stringValue.isEmpty == true ||
				tokenField.stringValue.localizedCaseInsensitiveContains(searchField.stringValue)
			{
				filteredHint = Hint(tokenField.stringValue)
				filteredHintIndex! += 1
			}
		}
		
		if filteredHint != nil
		{
			elementsFiltered[filteredGroupIndex!].hints!.insert(filteredHint!, at:filteredHintIndex!)
			elementsView.reloadData()
		}
		else
		{
			guard
				let groupIdx = elements.index(where: {$0.name == elementsFiltered[filteredGroupIndex!].name}),
				let hintIdx = elements[realGroupIdx].hints.index(where: {$0.token == tokenField.stringValue})
			else
			{
				return
			}

			// reset search filter
			searchField.stringValue = ""
			filterHints(for: searchField.stringValue)
			
			filteredGroupIndex = groupIdx
			filteredHintIndex = hintIdx
			
			elementsView.reloadData()
			
			elementsView.expandItem(elementsFiltered[groupIdx], expandChildren: false)
			filteredHint = elementsFiltered[groupIdx].hints[hintIdx]
		}

		// move selection to the new element
		DispatchQueue.main.async {
			let rowIndex = self.elementsView.row(forItem: filteredHint)
			if rowIndex != -1
			{
				self.elementsView.selectRowIndexes(IndexSet(integer:rowIndex), byExtendingSelection: false)
			}
		}
	}
	
	@IBAction func deleteHint(_ sender: Any)
	{
		guard
			filteredGroupIndex != nil,
			filteredHintIndex != nil,
			let realGroupIdx = elements.index(where: {$0.name == elementsFiltered[filteredGroupIndex!].name}),
			let realHintIdx = elements[realGroupIdx].hints.index(where: {$0.token == tokenField.stringValue}),
			let element = xmlDoc?.root["elements"]["group"].all![realGroupIdx]["hint"].all![realHintIdx]
		else {
			return
		}
		
		clearFields()
		
		element.removeFromParent()
		elements[realGroupIdx].hints!.remove(at: realHintIdx)
		elementsFiltered[filteredGroupIndex!].hints!.remove(at: filteredHintIndex!)

		clearFields()
	
		filteredGroupIndex = nil
		filteredHintIndex = nil
		
		updateButtonStates()
		
		elementsView.reloadData()
	}

	@IBAction func searchHint(_ sender: Any)
	{
		clearFields();
		
		updateButtonStates()
		
		filterHints(for: (sender as! NSSearchField).stringValue)
	}
}

// MARK: NSTextFieldDelegate

extension ViewController: NSTextFieldDelegate
{
	override func controlTextDidChange(_ notification: Notification)
	{
		guard let textField = notification.object as? NSTextField else {
			return
		}
		
		if [ tokenField, docField, pageField, headerField ].contains(textField)
		{
			generatePreview()
			
			updateButtonStates()
		}
	}
}

// MARK: NSControlTextEditingDelegate

extension ViewController: NSControlTextEditingDelegate
{
	// replace TAB with spaces
	func control(_ control: NSControl, textView: NSTextView, doCommandBy commandSelector: Selector) -> Bool
	{
		var result = false
		
		if commandSelector == #selector(NSResponder.insertTab(_:))
		{
			if textView === headerField
			{
				let TAB = String(repeating: " ", count: 4)
				textView.insertText(TAB, replacementRange: NSMakeRange(textView.string!.characters.count, textView.string!.characters.count))
				result = true
			}
		}

		return result
	}
}


extension ViewController: NSTextViewDelegate
{
	func textDidChange(_ notification: Notification)
	{
		guard let textView = notification.object as? NSTextView else {
			return
		}
		
		if infoField === textView
		{
			generatePreview()
			
			updateButtonStates()
		}
	}
}

// MARK: NSOutlineViewDataSource

extension ViewController: NSOutlineViewDataSource
{
	func outlineView(_ outlineView: NSOutlineView, numberOfChildrenOfItem item: Any?) -> Int
	{
		guard xmlDoc != nil else {
			return 0
		}
		
		if let group = item as? Group
		{
			return group.hints.count
		}
		return elementsFiltered.count
	}
	
	func outlineView(_ outlineView: NSOutlineView, child index: Int, ofItem item: Any?) -> Any
	{
		if let group = item as? Group
		{
			return group.hints[index]
		}
		
		return elementsFiltered[index]
	}
	
	func outlineView(_ outlineView: NSOutlineView, isItemExpandable item: Any) -> Bool
	{
		if let group = item as? Group
		{
			return group.hints.count > 0
		}
		
		return false
	}
}

// MARK: NSOutlineViewDelegate

extension ViewController: NSOutlineViewDelegate {
	func outlineView(_ outlineView: NSOutlineView, viewFor tableColumn: NSTableColumn?, item: Any) -> NSView?
	{
		var view: NSTableCellView?
		
		var text = ""
		
		if let group = item as? Group
		{
			text = group.name
		}
		
		if let hint = item as? Hint
		{
			text = hint.token
		}
		
		view = outlineView.make(withIdentifier: "ElementCell", owner: self) as? NSTableCellView
		if let textField = view?.textField
		{
			textField.stringValue = text
			textField.sizeToFit()
			
			
			if let font = textField.font
			{
				if item is Group
				{
					textField.font = NSFontManager.shared().convert(font, toHaveTrait: .boldFontMask)
				}
				else
				{
					textField.font = NSFontManager.shared().convert(font, toHaveTrait: .unboldFontMask)
				}
			}
		}
		
		return view
	}
	
	func outlineViewSelectionDidChange(_ notification: Notification)
	{
		guard let outlineView = notification.object as? NSOutlineView else {
			return
		}
		
		let selectedIndex = outlineView.selectedRow
		
		guard selectedIndex != -1 else {
			clearFields()

			filteredGroupIndex = nil
			filteredHintIndex = nil
			
			updateButtonStates()
			
			return
		}

		if let hint = outlineView.item(atRow: selectedIndex) as? Hint
		{
			guard
				let group = outlineView.parent(forItem: hint) as? Group,
				let groupIndex = elementsFiltered.index(where: { $0 === group } ),
				let hintIndex = group.hints.index(where: { $0 === hint } )
			else {
				print("HintEditor: Unable to get element with index \(selectedIndex)")
				return
			}
			
			filteredGroupIndex = groupIndex
			filteredHintIndex = hintIndex
			
			guard
				let realGroupIdx = elements.index(where: {$0.name == group.name}),
				let realHintIdx = elements[realGroupIdx].hints.index(where: {$0.token == hint.token})
			else
			{
				return
			}
			
			deleteButton.isEnabled = true
			readHint(groupIndex: realGroupIdx, hintIndex: realHintIdx)
		}
		else
		{
			guard
				let group = outlineView.item(atRow: selectedIndex) as? Group,
				let groupIndex = elementsFiltered.index(where: { $0 === group } )
			else {
				print("HintEditor: Unable to get element with index \(selectedIndex)")
				return
			}
			
			clearFields()

			filteredGroupIndex = groupIndex
			filteredHintIndex = nil

			updateButtonStates()
		}
	}
}
