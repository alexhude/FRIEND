//
//  AppDelegate.swift
//  HintEditor
//
//  Created by Alexander Hude on 10/11/2016.
//  Copyright © 2016 Fried Apple. All rights reserved.
//

import Cocoa
import AEXML

@NSApplicationMain
class AppDelegate: NSObject, NSApplicationDelegate {
	
	@IBOutlet weak var window: NSWindow!
	
	func applicationDidFinishLaunching(_ aNotification: Notification) {
		// Insert code here to initialize your application
	}
	
	func applicationWillTerminate(_ aNotification: Notification) {
		// Insert code here to tear down your application
	}
	
	func applicationShouldTerminateAfterLastWindowClosed(_ sender: NSApplication) -> Bool {
		return true
	}
	
}

