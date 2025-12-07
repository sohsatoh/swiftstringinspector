# Swift String Inspector Plugin

An advanced IDA Pro 9.x plugin for comprehensive Swift and Objective-C analysis during reverse engineering of iOS ARM64 binaries. This enhanced version significantly extends the original functionality with multiple detection patterns, Swift metadata scanning, Objective-C bridge support, and an interactive results viewer with advanced filtering capabilities.

## 🚀 Enhanced Features

### 1. Multiple String Detection Patterns

- Pattern 1: Original ADRL/SUB - Classic Swift string detection
- Pattern 2: ADRP/ADD - Page-based addressing for modern ARM64
- Pattern 3: Inline MOV strings - Small strings stored directly in instructions
- Pattern 4: C String Section - Comprehensive `__cstring` scanning with Swift mangled symbol detection

### 2. Advanced Swift Structure Analysis

- Type Metadata Scanner - Discovers Swift type information in `__swift5_types` section
- Protocol Scanner - Detects protocol conformances from `__swift5_proto`
- Enhanced Array Scanner - Analyzes Swift arrays with count/capacity information
- Demangling Support - Automatic Swift symbol demangling for better readability

### 3. Objective-C Bridge Support

- ObjC Selector Detection - Finds `@selector()` references from `__objc_selrefs`
- @objc Class Detection - Identifies Swift classes bridged to Objective-C
- Essential for mixed Swift/ObjC codebases - Common in iOS applications

### 4. Cross-Reference Tracking

- XRef Analysis - Tracks all references to discovered strings
- Function Mapping - Shows which functions use which strings with function name display
- Code Flow Understanding - Helps trace string usage throughout the binary
- Function Context - Results display includes the function name where each string is found

### 5. Interactive Results Viewerwer

- Integrated Search Bar - Real-time string content filtering with 300ms debounce to prevent UI freezing
- Multi-Type Filtering - Filter by multiple detection types simultaneously (ADRL/SUB, Swift_Protocol, etc.)
  - Select/Deselect All options
  - Checkable menu for easy type selection
- Smart Grouping - Group identical strings to see:
  - Occurrence count per unique string
  - Aggregated cross-reference totals
  - Gray highlighting for grouped items
- Enhanced Display Columns:
  - Address - Location of the string reference
  - Function - Function name containing the reference
  - String Address - Actual string location in memory
  - Type - Detection method used
  - Content - String preview (truncated to 100 chars)
  - XRefs - Number of cross-references
- Performance Optimizations:
  - Maximum 1000 items displayed with overflow warning
  - Debounced search to prevent excessive redraws
  - Efficient filtering and grouping algorithms
- Color-Coded Results - Each detection type has a distinct background color
- Double-Click Navigation - Jump directly to address in IDA disassembly

### 6. Enhanced User Interface

- Organized Control Panel - Logical grouping of scanning functions:
  - String Detection Patterns
  - Swift Structure Analysis
  - Objective-C Bridge
  - Utilities
- Platform Detection - Displays processor type, ARM64 status, and iOS detection
- Statistics View - Comprehensive binary analysis statistics grouped by type
- Debug Mode Toggle - Runtime debug control for troubleshooting

### 7. Utility Features

- Auto-Annotation (Default ON) - Automatically adds `__SwiftStr: "..."` comments to inline strings for better readability in:
  - IDA disassembly view
  - Hex-Rays decompiler pseudo-code
  - Applied during both individual and comprehensive scans
- Export Functionality - Save all scan results to structured text files grouped by type
- Comprehensive Scan - Combines all detection methods with automatic deduplication
- Batch Processing - Efficient scanning with progress indicators
- Error Recovery - Safe memory reading with proper exception handling

### 8. Performance & Reliability

- Progress Indicators - Uses `show_wait_box` with status updates for long operations
- Caching Mechanisms - XRef and string caching for improved performance
- Safe Memory Access - Proper exception handling to prevent crashes
- UTF-8 Decoding - Error recovery for malformed strings
- Display Limits - Automatic truncation at 1000 items with refinement suggestions
- Debounced Input - 300ms delay on search to prevent excessive updates
- IDA Pro 9 Compatible - Updated for latest IDA Pro API

## 🎯 Usage

### Quick Start

1. Load your ARM64 iOS binary in IDA Pro 9.x
2. Press `Ctrl+Shift+S` or go to `Edit > Plugins > Swift String Inspector Enhanced`
3. Choose your scanning method:
   - Individual scans for targeted analysis
   - Comprehensive scan for complete analysis with deduplication

### Scanning Methods

#### String Detection Patterns

- ADRL/SUB Pattern - Original Swift string references
- ADRP/ADD Pattern - Modern page-based string addressing
- Inline MOV Strings - Immediate value strings (auto-annotated by default)
- C String Section - All strings in `__cstring` including Swift symbols

#### Swift Structure Analysis

- Type Metadata - Scan `__swift5_types` for type information
- Protocol Conformances - Discover protocol implementations
- Swift Arrays - Enhanced array detection with metadata

#### Objective-C Bridge

- ObjC Selectors - Detect `@selector()` references
- @objc Classes - Find Swift classes exposed to Objective-C

#### Utilities

- Auto-annotate (__SwiftStr) - Enabled by default; adds comments to inline strings
- Comprehensive Scan - Runs all detectors and removes duplicates
- Export Results - Save findings to a structured text file grouped by type
- Statistics - View detailed summary with counts by type and total XRefs

### Using the Results Viewer

1. Search Bar - Type to filter results by string content (300ms debounce)
2. Filter Types Button - Click to:
   - Select specific detection types to display
   - Use "Select All" or "Deselect All" for quick changes
   - Multiple types can be selected simultaneously
3. Group by String Content - Check to aggregate duplicate strings:
   - Shows occurrence count
   - Displays total XRef count across all instances
   - Groups appear in gray
4. Double-Click - Navigate to the address in IDA
5. Column Sorting - Click headers to sort by any column

## 🛠 Installation

1. Copy `swift_string_inspector.py` to your IDA plugins folder:
   - Windows: `C:\Program Files\IDA Pro 9.0\plugins\`
   - macOS: `/Applications/IDA Pro 9.0/ida.app/Contents/MacOS/plugins/`
   - Linux: `~/.idapro/plugins/`

2. Restart IDA Pro

## 📝 Requirements

- IDA Pro 9.x
- Python 3.x

## 🔧 Technical Details

### Results Display

The results viewer displays up to 1000 items at once to prevent UI freezing. If more results are found, a warning message appears with the overflow count, prompting you to refine your search or type filters.

### Auto-Annotation

When enabled (default), the plugin adds IDA comments in the format:

```
"detected string content"
```

This improves readability in:

- Disassembly view (next to MOV instructions)
- Hex-Rays decompiler output
- Cross-reference listings

### Detection Type Colors

- ADRL/SUB: Light Green
- ADRP/ADD: Light Cyan
- MOV_Inline: Light Red
- CString_Swift: Light Yellow
- Swift_TypeMetadata: Light Magenta
- Swift_Protocol: Light Blue
- ObjC_Selector: Light Orange
- ObjC_Class: Light Lime
- Grouped Items: Light Gray

## 📜 License

MIT License - See LICENSE file for details.

Original work by @Keowu (github.com/keowu/swiftstringinspector)
Enhanced by @sohsatoh

## 🤝 Contributing

Contributions are welcome! Feel free to:

- Report bugs or issues
- Suggest new features
- Submit pull requests

## 📧 Support

For issues or questions:

- Open an issue on GitHub
- Check existing issues for solutions

---

Note: This plugin works best with ARM64 iOS binaries. While it may detect some patterns in other architectures, optimal results are achieved with iOS applications.
