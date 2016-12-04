# FRIEND
**F**lexible **R**egister/**I**nstruction **E**xtender a**N**d **D**ocumentation

[![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=W53WK5JGSESY6)

## Features

FRIEND is an IDA plugin created to improve disassembly and bring register/instruction documentation right into IDA View.

### 1. Improved processor modules using third party libraries (like Capstone)   
![](./Resources/screenshots/Capstone.png)

### 2. Hints for instructions and registers in IDA View   
![](./Resources/screenshots/BCC.png)
![](./Resources/screenshots/DSB_inst.png)
![](./Resources/screenshots/DSB_reg.png)
![](./Resources/screenshots/UMADDL.png)

### 3. Ability to show external reference for highlighted item in a browser    
![](./Resources/screenshots/ShowDoc.png)

### 4. Ability to pick only elements you are interested in
![](./Resources/screenshots/Settings.png)

## Configuration files

The content of hints is discussed [here](https://github.com/alexhude/FRIEND/issues/1)

FRIEND configuration file has following structure:

```
<?xml version="1.0" encoding="utf-8" standalone="no"?>
<documentation>
	<document id="pdf_id" name="ARM Architecture Reference Manual" version="A.k">
		<path>/path/to/your/pdf</path>
	</document>
	<elements>
		<group type="reg" name="Group Name">
			<hint page="1" header="Element Header" doc_id="pdf_id" token="R0">info</>
			...
		</group>
		<group type="ins" name="Group Name">
			<hint page="2" header="Element Header" doc_id="pdf_id" token="MOV">info</>
			...
		</group>
		...
	</elements>
</documentation>
```

Please note that you have to put your own \<path\> to pdf file to be able to use external documentation in a browser.

## Hint Editor
To make contribution to this project easier, there is a simple config editor.
![](./Resources/screenshots/HintEditor.png)

## Dependencies

FRIEND requires:  
- [IDA SDK](https://www.hex-rays.com/products/ida/support/download.shtml)   
- [Capstone](https://github.com/aquynh/capstone) (built with Patches/capstone.diff)  
- [pugixml](https://github.com/zeux/pugixml)

Hint Editor requires:  
- [AEXML](https://github.com/tadija/AEXML) (built with Patches/aexml.diff)  

## Credits

@ **in7egral, mbazaliy** for bug reports and all kind of support    
@ __qwertyoruiopz, iH8sn0w, Morpheus\_\_\_\_\_\_, xerub, msolnik, marcograss, pr0x13, \_argp, oleavr, brinlyau__ and other gang for inspiration  