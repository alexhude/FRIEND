# FRIEND

**F**lexible **R**egister/**I**nstruction **E**xtender a**N**d **D**ocumentation

## Features

FRIEND is an IDA plugin created to improve disassembly and bring register/instruction documentation right into IDA View.

### 1. Improved processor modules using third party libraries (like Capstone)   

![](./Resources/screenshots/proc_ext.png)

### 2. Hints for instructions and registers in IDA View and Decompiler View   

![](./Resources/screenshots/reg_ins_hints.png)

### 3. Ability to show external reference for highlighted item in a browser    

![](./Resources/screenshots/external_doc.png)

### 4. Function Summary in IDA View and Decompiler View   

![](./Resources/screenshots/summary.png)

### 5. Ability to pick only elements you are interested in

![](./Resources/screenshots/settings.png)

## How to build

### Preparing the build environment

To build the IDA plugin, there are few dependencies to satisfy:

* [CMake](https://cmake.org/download/) 3.3 or higher
* GCC or Clang on Linux/macOS. On Windows, use the
  Visual Studio 2015.
* Git
* IDA SDK (unpack into ``idasdk``)
* Hex-Rays SDK (copy to ``hexrays_sdk``)

Unzip the contents of the IDA SDK into `idasdk`, and copy the Hex-Rays SDK to hexrays_sdk. On Linux or MacOS, one can use the following commands:

```sh
$ unzip /path/to/idasdk69.zip -d idasdk
$ mv idasdk/idasdk69/* idasdk
$ rm -r idasdk/idasdk69
$ cp -r /path/to/ida/plugins/hexrays_sdk hexrays_sdk
```

### Linux

Use ``cmake`` to prepare the build environment and run ``make`` to build the plugins:

```sh
$ mkdir _build
$ cd _build
$ cmake ..
$ make
```

### MacOS

Use ``cmake`` to prepare the build environment and run ``make`` to build the plugins:

```sh
$ mkdir _build
$ cd _build
$ cmake ..
$ make
```

If you prefer to have an Xcode project and build everything from there, run the following commands instead:

```sh
$ mkdir _build
$ cd _build
$ cmake -G Xcode ..
$ open FRIEND.xcodeproj # or simply run xcodebuild
```

### Windows

Use ``cmake`` to prepare the build environment and run ``make`` to build the plugins:

```sh
$ mkdir _build
$ cd _build
$ "%VS140COMNTOOLS%\..\..\VC\vcvarsall.bat" x86
$ cmake -G "Visual Studio 14 2015" ..
$ msbuild FRIEND.sln /p:Configuration=Release
```

## Installation

Copy the built binaries into the IDA Pro plugins directory. These are the default paths:

OS      | Plugin path
--------|-------------------------------------------
Linux   | `/opt/ida-6.95/plugins`
macOS   | `/Applications/IDA Pro 6.95/idabin/plugins`
Windows | `%ProgramFiles(x86)%\IDA 6.95\plugins`

## Configuration files

The content of hints is discussed [here](https://github.com/alexhude/FRIEND/issues/1)

FRIEND configuration file has following structure:

```
<?xml version="1.0" encoding="utf-8" standalone="no"?>
<documentation>
	<document id="pdf_id" name="ARM Architecture Reference Manual" version="A.k">
		<path>/path/to/your/pdf/or/link</path>
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
![](./Resources/screenshots/hint_editor.png)

__NOTE:__ It can only be built on MacOS with Xcode 8 or higher. Other systems are not supported.

Use ``cmake`` to generate Xcode project.

```sh
$ cd HintEditor/HintEditor/
$ mkdir _build
$ cd _build
$ cmake -G Xcode ..
$ xcodebuild
```

Launch the application bundle with ``open``:

```
$ open Debug/HintEditor.app
```

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
@ __\_kamino\___ for porting project to Windows and Linux  
@ __williballenthin__ for the idea of function summary
