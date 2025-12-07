# (C) @Keowu - github.com/keowu/swiftstringinspector - 2025
# Enhanced by Advanced Swift/ObjC Bridge Analysis Features for IDA Pro 9
import idaapi
import ida_kernwin
import idautils
import ida_ida
import ida_segment
import ida_bytes
import ida_name
import ida_xref
import ida_funcs
import struct
import idc
import re
from collections import defaultdict
from PyQt5 import QtWidgets, QtCore, QtGui

# IDA Pro 9 Compatible Constants
NN_adr = 81  # ADRL instruction
NN_adrp = 82  # ADRP instruction (page-based addressing)
NN_add = 0  # ADD instruction
NN_mov = 80  # MOV instruction
NN_sub = 12  # SUB instruction
NM_x8 = 137  # X8 register
o_mem = 5  # Memory operand
o_reg = 1  # Register operand
o_imm = 5  # Immediate operand
dt_qword = 7  # QWORD data type

# CONSTANTS
OFFSET_CONSTANT = 0x20
ADDRESSING_MASK = 0x8000000000000000
PAGE_SIZE = 0x1000
DEBUG_ENABLED = False

# Global cache for performance
_xref_cache = {}


def debug_print(msg):
    """Debug print helper"""
    if DEBUG_ENABLED:
        print(f"[SwiftInspector] {msg}")


def safe_read_bytes(ea, size):
    """Safely read bytes with error handling"""
    try:
        return ida_bytes.get_bytes(ea, size)
    except Exception as e:
        debug_print(f"Failed to read {size} bytes at 0x{ea:x}: {e}")
        return None


def safe_decode_string(data, encoding="utf-8"):
    """Safely decode string with fallback"""
    if not data:
        return None
    try:
        return data.decode(encoding, errors="ignore")
    except Exception as e:
        debug_print(f"Failed to decode string: {e}")
        return None


def get_platform_info():
    """Detect binary platform"""
    info = ida_ida.inf_get_procname()
    filetype = ida_ida.inf_get_filetype()
    is_arm64 = "ARM" in info or "arm" in info
    is_ios = filetype == ida_ida.f_MACHO
    return {
        "processor": info,
        "is_arm64": is_arm64,
        "is_ios": is_ios,
        "is_macho": filetype == ida_ida.f_MACHO,
    }


def get_segment_by_name(name):
    """Get segment by name"""
    for ea in idautils.Segments():
        seg = ida_segment.getseg(ea)
        if seg:
            seg_name = ida_segment.get_segm_name(seg)
            if name in seg_name:
                return ea
    return None


def get_xrefs_to(ea):
    """Get cross-references to address with caching"""
    if ea in _xref_cache:
        return _xref_cache[ea]

    xrefs = []
    for xref in idautils.XrefsTo(ea):
        func = ida_funcs.get_func(xref.frm)
        func_name = ida_funcs.get_func_name(xref.frm) if func else "unknown"
        xrefs.append({"from": xref.frm, "type": xref.type, "func": func_name})

    _xref_cache[ea] = xrefs
    return xrefs


def demangle_name(name):
    """Demangle Swift/C++ names"""
    if not name:
        return None
    demangled = idc.demangle_name(name, idc.get_inf_attr(idc.INF_SHORT_DN))
    return demangled if demangled else name


class StringDetector:
    """Advanced string detection with multiple patterns"""

    @staticmethod
    def detect_adrl_sub_pattern(ea, inst):
        """Pattern 1: Original ADRL/SUB pattern"""
        if (
            inst.itype == NN_adr
            and inst[0].reg == NM_x8
            and inst[1].type == idaapi.o_imm
        ):
            inst2 = idautils.DecodeInstruction(ea + inst.size)
            if (
                inst2
                and inst2.itype == NN_sub
                and inst2[0].reg == NM_x8
                and inst2[2].value == OFFSET_CONSTANT
            ):
                string_bytes = idc.get_strlit_contents(inst[1].value, -1, idc.STRTYPE_C)
                if string_bytes:
                    decoded = safe_decode_string(string_bytes)
                    if decoded:
                        xrefs = get_xrefs_to(ea)
                        return {
                            "ea": ea,
                            "string_ea": inst[1].value,
                            "string": decoded,
                            "type": "ADRL/SUB",
                            "xrefs": xrefs,
                        }
        return None

    @staticmethod
    def detect_adrp_add_pattern(ea, inst):
        """Pattern 2: ADRP/ADD pattern for page-based addressing"""
        if inst.itype == NN_adrp and inst[0].type == o_reg:
            reg = inst[0].reg
            inst2 = idautils.DecodeInstruction(ea + inst.size)
            if inst2 and inst2.itype == NN_add and inst2[0].reg == reg:
                # Calculate address: (ADRP page) + (ADD offset)
                page_base = inst[1].value & ~(PAGE_SIZE - 1)
                offset = inst2[2].value if inst2[2].type == o_imm else 0
                target_ea = page_base + offset

                string_bytes = idc.get_strlit_contents(target_ea, -1, idc.STRTYPE_C)
                if string_bytes:
                    decoded = safe_decode_string(string_bytes)
                    if decoded:
                        xrefs = get_xrefs_to(ea)
                        return {
                            "ea": ea,
                            "string_ea": target_ea,
                            "string": decoded,
                            "type": "ADRP/ADD",
                            "xrefs": xrefs,
                        }
        return None

    @staticmethod
    def detect_inline_mov_string(ea, inst):
        """Pattern 3: Inline strings in MOV instructions"""
        if (
            inst.itype == NN_mov
            and inst[0].dtype == dt_qword
            and inst[1].dtype == dt_qword
        ):
            big_endian = inst[1].value
            num_bytes = (big_endian.bit_length() + 7) // 8
            if num_bytes == 0:
                return None

            value_bytes = big_endian.to_bytes(num_bytes, byteorder="big")
            little_endian_value = int.from_bytes(value_bytes[::-1], byteorder="big")

            ascii_count = sum(
                1
                for i in range(num_bytes)
                if 0x00
                <= (little_endian_value >> (8 * (num_bytes - i - 1))) & 0xFF
                <= 0x7F
            )

            if ascii_count >= 4:
                result_string = little_endian_value.to_bytes(
                    (little_endian_value.bit_length() + 7) // 8, byteorder="big"
                ).decode("ascii", errors="replace")
                xrefs = get_xrefs_to(ea)
                return {
                    "ea": ea,
                    "string_ea": inst[1].value,
                    "string": result_string,
                    "type": "MOV_Inline",
                    "xrefs": xrefs,
                }
        return None

    @staticmethod
    def scan_cstring_section():
        """Pattern 4: Scan __cstring section"""
        results = []
        cstring_seg = get_segment_by_name("__cstring")
        if not cstring_seg:
            return results

        seg = ida_segment.getseg(cstring_seg)
        if not seg:
            return results

        ea = seg.start_ea
        while ea < seg.end_ea:
            string_bytes = idc.get_strlit_contents(ea, -1, idc.STRTYPE_C)
            if string_bytes:
                decoded = safe_decode_string(string_bytes)
                if decoded and len(decoded) > 3:  # Filter short strings
                    # Check if it's a Swift mangled name
                    is_swift_mangled = decoded.startswith("$s") or decoded.startswith(
                        "_$s"
                    )
                    xrefs = get_xrefs_to(ea)
                    results.append(
                        {
                            "ea": ea,
                            "string_ea": ea,
                            "string": decoded,
                            "type": "CString_Swift" if is_swift_mangled else "CString",
                            "xrefs": xrefs,
                        }
                    )
                    ea += len(string_bytes) + 1
                else:
                    ea += 1
            else:
                ea += 1
        return results


class SwiftMetadataScanner:
    """Advanced Swift structure analysis"""

    @staticmethod
    def scan_type_metadata():
        """Scan Swift type metadata in __swift5_types section"""
        results = []
        types_seg = get_segment_by_name("__swift5_types")
        if not types_seg:
            return results

        seg = ida_segment.getseg(types_seg)
        if not seg:
            return results

        ea = seg.start_ea
        while ea < seg.end_ea:
            # Swift type metadata structure
            data = safe_read_bytes(ea, 4)
            if data:
                type_ref = struct.unpack("<I", data)[0]
                name = ida_name.get_name(ea)
                if name:
                    demangled = demangle_name(name)
                    results.append(
                        {
                            "ea": ea,
                            "string_ea": ea,
                            "string": f"Type: {demangled or name}",
                            "type": "Swift_TypeMetadata",
                            "xrefs": get_xrefs_to(ea),
                        }
                    )
            ea += 4
        return results

    @staticmethod
    def scan_protocol_conformances():
        """Scan Swift protocol conformances"""
        results = []
        proto_seg = get_segment_by_name("__swift5_proto")
        if not proto_seg:
            return results

        seg = ida_segment.getseg(proto_seg)
        if not seg:
            return results

        ea = seg.start_ea
        while ea < seg.end_ea:
            name = ida_name.get_name(ea)
            if name:
                demangled = demangle_name(name)
                results.append(
                    {
                        "ea": ea,
                        "string_ea": ea,
                        "string": f"Protocol: {demangled or name}",
                        "type": "Swift_Protocol",
                        "xrefs": get_xrefs_to(ea),
                    }
                )
            ea += 4
        return results

    @staticmethod
    def scan_swift_arrays():
        """Enhanced Swift array scanner with count/capacity"""
        results = []
        ea = ida_ida.inf_get_min_ea()
        end_ea = ida_ida.inf_get_max_ea()

        while ea < end_ea:
            inst = idautils.DecodeInstruction(ea)
            if not inst:
                ea += 4
                continue

            if inst.itype == NN_adr and inst[0].type == o_reg and inst[1].type == o_mem:
                data = safe_read_bytes(inst[1].value, 8)
                if data:
                    value_swift = struct.unpack("<Q", data)[0]
                    if (value_swift & ADDRESSING_MASK) == ADDRESSING_MASK:
                        value_swift -= ADDRESSING_MASK
                        if (value_swift & 0xFF00000000000000) == 0:
                            # Try to read array count/capacity
                            array_data = safe_read_bytes(value_swift, 16)
                            count_info = ""
                            if array_data and len(array_data) >= 16:
                                count = struct.unpack("<Q", array_data[0:8])[0]
                                capacity = struct.unpack("<Q", array_data[8:16])[0]
                                count_info = f" [count:{count}, cap:{capacity}]"

                            results.append(
                                {
                                    "ea": ea,
                                    "string_ea": value_swift,
                                    "string": f"Swift::Array{count_info}",
                                    "type": "Swift_Array",
                                    "xrefs": get_xrefs_to(ea),
                                }
                            )
            ea += inst.size
        return results


class ObjCBridgeDetector:
    """Objective-C bridge support for Swift"""

    @staticmethod
    def scan_objc_selectors():
        """Detect Objective-C selectors"""
        results = []
        selrefs_seg = get_segment_by_name("__objc_selrefs")
        if not selrefs_seg:
            return results

        seg = ida_segment.getseg(selrefs_seg)
        if not seg:
            return results

        ea = seg.start_ea
        while ea < seg.end_ea:
            data = safe_read_bytes(ea, 8)
            if data:
                sel_ptr = struct.unpack("<Q", data)[0]
                sel_name_bytes = idc.get_strlit_contents(sel_ptr, -1, idc.STRTYPE_C)
                if sel_name_bytes:
                    sel_name = safe_decode_string(sel_name_bytes)
                    if sel_name:
                        results.append(
                            {
                                "ea": ea,
                                "string_ea": sel_ptr,
                                "string": f"@selector({sel_name})",
                                "type": "ObjC_Selector",
                                "xrefs": get_xrefs_to(ea),
                            }
                        )
            ea += 8
        return results

    @staticmethod
    def scan_objc_classes():
        """Detect @objc Swift classes"""
        results = []
        classlist_seg = get_segment_by_name("__objc_classlist")
        if not classlist_seg:
            return results

        seg = ida_segment.getseg(classlist_seg)
        if not seg:
            return results

        ea = seg.start_ea
        while ea < seg.end_ea:
            data = safe_read_bytes(ea, 8)
            if data:
                class_ptr = struct.unpack("<Q", data)[0]
                name = ida_name.get_name(class_ptr)
                if name:
                    demangled = demangle_name(name)
                    results.append(
                        {
                            "ea": ea,
                            "string_ea": class_ptr,
                            "string": f"@objc class: {demangled or name}",
                            "type": "ObjC_Class",
                            "xrefs": get_xrefs_to(ea),
                        }
                    )
            ea += 8
        return results


class SwiftInspectorResultsForm(ida_kernwin.PluginForm):
    """Results window with filtering and grouping"""

    def __init__(self, title, results):
        super().__init__()
        self.title = title
        self.results = results
        self.selected_types = set()

        # Debounce timer for search
        self.filter_timer = QtCore.QTimer()
        self.filter_timer.setSingleShot(True)
        self.filter_timer.setInterval(300)  # 300ms delay
        self.filter_timer.timeout.connect(self.refresh_list)

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.init_ui()

    def init_ui(self):
        layout = QtWidgets.QVBoxLayout()

        # Controls
        controls_layout = QtWidgets.QHBoxLayout()

        self.search_bar = QtWidgets.QLineEdit()
        self.search_bar.setPlaceholderText("Filter by string content...")
        self.search_bar.textChanged.connect(self.on_search_text_changed)

        self.chk_group = QtWidgets.QCheckBox("Group by String Content")
        self.chk_group.stateChanged.connect(self.refresh_list)

        # Type Filter Button
        self.btn_filter_type = QtWidgets.QPushButton("Filter Types")
        self.type_menu = QtWidgets.QMenu()
        self.btn_filter_type.setMenu(self.type_menu)
        self.update_type_menu()

        controls_layout.addWidget(self.search_bar)
        controls_layout.addWidget(self.btn_filter_type)
        controls_layout.addWidget(self.chk_group)
        layout.addLayout(controls_layout)

        # Tree
        self.tree = QtWidgets.QTreeWidget()
        self.tree.setColumnCount(6)
        self.tree.setHeaderLabels(
            ["Address", "Function", "String Address", "Type", "Content", "XRefs"]
        )
        self.tree.itemDoubleClicked.connect(self.on_item_dbl_click)
        self.tree.setSortingEnabled(True)
        layout.addWidget(self.tree)

        self.parent.setLayout(layout)
        self.refresh_list()

    def update_type_menu(self):
        """Update type filter menu based on current results"""
        self.type_menu.clear()
        if not self.results:
            return

        types = sorted(list(set(item["type"] for item in self.results)))
        # If selected_types is empty (first run), select all
        if not self.selected_types:
            self.selected_types = set(types)

        # Add "Select All" action
        all_action = QtWidgets.QAction("Select All", self.parent)
        all_action.triggered.connect(self.select_all_types)
        self.type_menu.addAction(all_action)

        # Add "Deselect All" action
        none_action = QtWidgets.QAction("Deselect All", self.parent)
        none_action.triggered.connect(self.deselect_all_types)
        self.type_menu.addAction(none_action)

        self.type_menu.addSeparator()

        for t in types:
            action = QtWidgets.QAction(t, self.parent, checkable=True)
            action.setChecked(t in self.selected_types)
            action.triggered.connect(
                lambda checked, type_name=t: self.on_type_toggled(type_name, checked)
            )
            self.type_menu.addAction(action)

    def select_all_types(self):
        types = set(item["type"] for item in self.results)
        self.selected_types = types
        self.update_type_menu()
        self.refresh_list()

    def deselect_all_types(self):
        self.selected_types = set()
        self.update_type_menu()
        self.refresh_list()

    def on_type_toggled(self, type_name, checked):
        if checked:
            self.selected_types.add(type_name)
        else:
            self.selected_types.discard(type_name)
        self.refresh_list()

    def on_search_text_changed(self, text):
        """Debounce search input"""
        self.filter_timer.start()

    def refresh_list(self):
        self.tree.clear()
        search_text = self.search_bar.text().lower()
        group_enabled = self.chk_group.isChecked()

        filtered = self.results

        # Filter by type
        if self.selected_types:
            filtered = [
                item for item in filtered if item["type"] in self.selected_types
            ]

        if search_text:
            filtered = [
                item for item in filtered if search_text in item["string"].lower()
            ]

        display_items = filtered
        if group_enabled:
            grouped = {}
            for item in filtered:
                content = item["string"]
                if content not in grouped:
                    grouped[content] = item.copy()
                    grouped[content]["count"] = 1
                    grouped[content]["xrefs_count"] = len(item.get("xrefs", []))
                    grouped[content]["type"] = "Grouped (1)"
                else:
                    grouped[content]["count"] += 1
                    grouped[content]["xrefs_count"] += len(item.get("xrefs", []))
                    grouped[content]["type"] = f"Grouped ({grouped[content]['count']})"
            display_items = list(grouped.values())

        # Populate
        items = []
        MAX_ITEMS = 1000  # Limit display items to prevent UI freeze

        for i, data in enumerate(display_items):
            if i >= MAX_ITEMS:
                # Add warning item
                warning = QtWidgets.QTreeWidgetItem(self.tree)
                warning.setText(
                    4,
                    f"... {len(display_items) - MAX_ITEMS} more items hidden. Please refine search.",
                )
                for col in range(6):
                    warning.setBackground(col, QtGui.QColor(0xFF, 0xE0, 0xE0))
                items.append(warning)
                break

            xref_count = data.get("xrefs_count", len(data.get("xrefs", [])))
            func_name = ida_funcs.get_func_name(data["ea"]) or ""

            item = QtWidgets.QTreeWidgetItem(self.tree)
            item.setText(0, f"0x{data['ea']:x}")
            item.setText(1, func_name)
            item.setText(2, f"0x{data['string_ea']:x}")
            item.setText(3, data["type"])
            item.setText(4, data["string"][:100])
            item.setText(5, str(xref_count))

            # Color
            color = self.get_color(data["type"])
            if color:
                for i in range(6):
                    item.setBackground(i, color)

            # Store EA for jump
            item.setData(0, QtCore.Qt.UserRole, data["ea"])
            items.append(item)

        self.tree.addTopLevelItems(items)

    def get_color(self, item_type):
        if "Grouped" in item_type:
            return QtGui.QColor(0xE0, 0xE0, 0xE0)

        colors = {
            "ADRL/SUB": (0xCC, 0xFF, 0xCC),
            "ADRP/ADD": (0xCC, 0xFF, 0xFF),
            "MOV_Inline": (0xFF, 0xCC, 0xCC),
            "CString_Swift": (0xFF, 0xFF, 0xCC),
            "Swift_TypeMetadata": (0xFF, 0xCC, 0xFF),
            "Swift_Protocol": (0xCC, 0xCC, 0xFF),
            "ObjC_Selector": (0xFF, 0xE0, 0xCC),
            "ObjC_Class": (0xE0, 0xFF, 0xCC),
        }
        rgb = colors.get(item_type)
        if rgb:
            return QtGui.QColor(*rgb)
        return None

    def on_item_dbl_click(self, item, column):
        ea = item.data(0, QtCore.Qt.UserRole)
        idaapi.jumpto(ea)

    def update_items(self, items):
        """Update items and refresh list"""
        self.results = items
        self.selected_types = set()  # Reset selection on new scan
        self.update_type_menu()
        self.refresh_list()

    def Show(self):
        return ida_kernwin.PluginForm.Show(
            self, self.title, options=ida_kernwin.PluginForm.WOPN_PERSIST
        )


class SwiftStringInspectorForm(ida_kernwin.PluginForm):
    """Enhanced main form with organized features"""

    def __init__(self):
        super().__init__()
        self.all_results = []
        self.platform_info = get_platform_info()
        self.chooser = None

    def OnCreate(self, form):
        self.parent = self.FormToPyQtWidget(form)
        self.init_ui()

    def init_ui(self):
        layout = QtWidgets.QVBoxLayout()

        # Platform info
        info_label = QtWidgets.QLabel(
            f"Platform: {self.platform_info['processor']} | "
            f"ARM64: {self.platform_info['is_arm64']} | "
            f"iOS: {self.platform_info['is_ios']}"
        )
        layout.addWidget(info_label)

        # Group 1: String Detection
        group_strings = QtWidgets.QGroupBox("String Detection Patterns")
        strings_layout = QtWidgets.QVBoxLayout()

        btn_adrl_sub = QtWidgets.QPushButton("ADRL/SUB Pattern")
        btn_adrp_add = QtWidgets.QPushButton("ADRP/ADD Pattern")
        btn_inline = QtWidgets.QPushButton("Inline MOV Strings")
        btn_cstring = QtWidgets.QPushButton("C String Section")

        btn_adrl_sub.clicked.connect(lambda: self.scan_pattern("adrl_sub"))
        btn_adrp_add.clicked.connect(lambda: self.scan_pattern("adrp_add"))
        btn_inline.clicked.connect(lambda: self.scan_pattern("inline"))
        btn_cstring.clicked.connect(lambda: self.scan_pattern("cstring"))

        strings_layout.addWidget(btn_adrl_sub)
        strings_layout.addWidget(btn_adrp_add)
        strings_layout.addWidget(btn_inline)
        strings_layout.addWidget(btn_cstring)
        group_strings.setLayout(strings_layout)
        layout.addWidget(group_strings)

        # Group 2: Swift Metadata
        group_swift = QtWidgets.QGroupBox("Swift Structure Analysis")
        swift_layout = QtWidgets.QVBoxLayout()

        btn_types = QtWidgets.QPushButton("Type Metadata")
        btn_protocols = QtWidgets.QPushButton("Protocol Conformances")
        btn_arrays = QtWidgets.QPushButton("Swift Arrays")

        btn_types.clicked.connect(lambda: self.scan_swift("types"))
        btn_protocols.clicked.connect(lambda: self.scan_swift("protocols"))
        btn_arrays.clicked.connect(lambda: self.scan_swift("arrays"))

        swift_layout.addWidget(btn_types)
        swift_layout.addWidget(btn_protocols)
        swift_layout.addWidget(btn_arrays)
        group_swift.setLayout(swift_layout)
        layout.addWidget(group_swift)

        # Group 3: ObjC Bridge
        group_objc = QtWidgets.QGroupBox("Objective-C Bridge")
        objc_layout = QtWidgets.QVBoxLayout()

        btn_selectors = QtWidgets.QPushButton("ObjC Selectors")
        btn_classes = QtWidgets.QPushButton("@objc Classes")

        btn_selectors.clicked.connect(lambda: self.scan_objc("selectors"))
        btn_classes.clicked.connect(lambda: self.scan_objc("classes"))

        objc_layout.addWidget(btn_selectors)
        objc_layout.addWidget(btn_classes)
        group_objc.setLayout(objc_layout)
        layout.addWidget(group_objc)

        # Group 4: Utilities
        group_utils = QtWidgets.QGroupBox("Utilities")
        utils_layout = QtWidgets.QVBoxLayout()

        self.chk_annotate = QtWidgets.QCheckBox("Auto-annotate")
        self.chk_annotate.setChecked(True)  # Default to ON

        btn_comprehensive = QtWidgets.QPushButton("🔍 Comprehensive Scan")
        btn_export = QtWidgets.QPushButton("💾 Export Results")
        btn_stats = QtWidgets.QPushButton("📊 Statistics")
        btn_debug = QtWidgets.QPushButton("🐛 Toggle Debug")
        btn_about = QtWidgets.QPushButton("ℹ️ About")

        btn_comprehensive.clicked.connect(self.comprehensive_scan)
        btn_export.clicked.connect(self.export_results)
        btn_stats.clicked.connect(self.show_statistics)
        btn_debug.clicked.connect(self.toggle_debug)
        btn_about.clicked.connect(self.on_about)

        utils_layout.addWidget(self.chk_annotate)
        utils_layout.addWidget(btn_comprehensive)
        utils_layout.addWidget(btn_export)
        utils_layout.addWidget(btn_stats)
        utils_layout.addWidget(btn_debug)
        utils_layout.addWidget(btn_about)
        group_utils.setLayout(utils_layout)
        layout.addWidget(group_utils)

        self.parent.setLayout(layout)

    def annotate_result(self, item):
        """Annotate result in IDB"""
        if "Inline" in item["type"]:
            # Add comment for inline strings
            ida_bytes.set_cmt(item["ea"], f"\"{item['string']}\"", 0)

    def scan_pattern(self, pattern_type):
        """Scan specific string pattern"""
        ida_kernwin.show_wait_box(f"Scanning {pattern_type} pattern...")

        try:
            results = []
            ea = ida_ida.inf_get_min_ea()
            end_ea = ida_ida.inf_get_max_ea()

            if pattern_type == "cstring":
                results = StringDetector.scan_cstring_section()
            else:
                while ea < end_ea:
                    inst = idautils.DecodeInstruction(ea)
                    if not inst:
                        ea += 4
                        continue

                    if pattern_type == "adrl_sub":
                        result = StringDetector.detect_adrl_sub_pattern(ea, inst)
                    elif pattern_type == "adrp_add":
                        result = StringDetector.detect_adrp_add_pattern(ea, inst)
                    elif pattern_type == "inline":
                        result = StringDetector.detect_inline_mov_string(ea, inst)
                    else:
                        result = None

                    if result:
                        results.append(result)
                        if self.chk_annotate.isChecked():
                            self.annotate_result(result)

                    ea += inst.size

            self.all_results.extend(results)
            self.show_results(results, f"{pattern_type.upper()} Pattern Results")
        finally:
            ida_kernwin.hide_wait_box()

    def scan_swift(self, scan_type):
        """Scan Swift metadata"""
        ida_kernwin.show_wait_box(f"Scanning Swift {scan_type}...")

        try:
            if scan_type == "types":
                results = SwiftMetadataScanner.scan_type_metadata()
            elif scan_type == "protocols":
                results = SwiftMetadataScanner.scan_protocol_conformances()
            elif scan_type == "arrays":
                results = SwiftMetadataScanner.scan_swift_arrays()
            else:
                results = []

            self.all_results.extend(results)
            self.show_results(results, f"Swift {scan_type.title()} Results")
        finally:
            ida_kernwin.hide_wait_box()

    def scan_objc(self, scan_type):
        """Scan ObjC bridge components"""
        ida_kernwin.show_wait_box(f"Scanning ObjC {scan_type}...")

        try:
            if scan_type == "selectors":
                results = ObjCBridgeDetector.scan_objc_selectors()
            elif scan_type == "classes":
                results = ObjCBridgeDetector.scan_objc_classes()
            else:
                results = []

            self.all_results.extend(results)
            self.show_results(results, f"ObjC {scan_type.title()} Results")
        finally:
            ida_kernwin.hide_wait_box()

    def comprehensive_scan(self):
        """Run all scans and deduplicate"""
        ida_kernwin.show_wait_box("Running comprehensive scan...")

        try:
            all_results = []

            # String patterns
            ida_kernwin.replace_wait_box("Scanning string patterns...")
            ea = ida_ida.inf_get_min_ea()
            end_ea = ida_ida.inf_get_max_ea()

            while ea < end_ea:
                inst = idautils.DecodeInstruction(ea)
                if inst:
                    for detector in [
                        StringDetector.detect_adrl_sub_pattern,
                        StringDetector.detect_adrp_add_pattern,
                        StringDetector.detect_inline_mov_string,
                    ]:
                        result = detector(ea, inst)
                        if result:
                            all_results.append(result)
                            if self.chk_annotate.isChecked():
                                self.annotate_result(result)
                    ea += inst.size
                else:
                    ea += 4

            # CString section
            ida_kernwin.replace_wait_box("Scanning CString section...")
            all_results.extend(StringDetector.scan_cstring_section())

            # Swift metadata
            ida_kernwin.replace_wait_box("Scanning Swift metadata...")
            all_results.extend(SwiftMetadataScanner.scan_type_metadata())
            all_results.extend(SwiftMetadataScanner.scan_protocol_conformances())
            all_results.extend(SwiftMetadataScanner.scan_swift_arrays())

            # ObjC bridge
            ida_kernwin.replace_wait_box("Scanning ObjC bridge...")
            all_results.extend(ObjCBridgeDetector.scan_objc_selectors())
            all_results.extend(ObjCBridgeDetector.scan_objc_classes())

            # Deduplicate
            ida_kernwin.replace_wait_box("Deduplicating results...")
            seen = set()
            deduped = []
            for item in all_results:
                key = (item["ea"], item["string"])
                if key not in seen:
                    seen.add(key)
                    deduped.append(item)

            self.all_results = deduped
            self.show_results(deduped, "Comprehensive Scan Results")
        finally:
            ida_kernwin.hide_wait_box()

    def show_results(self, results, title):
        """Display results in chooser"""
        if not results:
            idaapi.info("No results found")
            return

        self.chooser = SwiftInspectorResultsForm(title, results)
        self.chooser.Show()

    def export_results(self):
        """Export results to file"""
        if not self.all_results:
            idaapi.warning("No results to export. Run a scan first.")
            return

        filename = ida_kernwin.ask_file(True, "*.txt", "Export results to")
        if not filename:
            return

        try:
            with open(filename, "w", encoding="utf-8") as f:
                f.write("Swift String Inspector - Export Results\n")
                f.write("=" * 80 + "\n\n")

                # Group by type
                by_type = defaultdict(list)
                for item in self.all_results:
                    by_type[item["type"]].append(item)

                for type_name, items in sorted(by_type.items()):
                    f.write(f"\n{type_name} ({len(items)} items)\n")
                    f.write("-" * 80 + "\n")

                    for item in items:
                        f.write(f"Address: 0x{item['ea']:x}\n")
                        f.write(f"String EA: 0x{item['string_ea']:x}\n")
                        f.write(f"Content: {item['string']}\n")

                        xrefs = item.get("xrefs", [])
                        if xrefs:
                            f.write(f"Cross-references ({len(xrefs)}):\n")
                            for xref in xrefs[:10]:  # Limit to 10
                                f.write(f"  - 0x{xref['from']:x} in {xref['func']}\n")
                        f.write("\n")

            idaapi.info(f"Exported {len(self.all_results)} items to {filename}")
        except Exception as e:
            idaapi.warning(f"Export failed: {e}")

    def show_statistics(self):
        """Show analysis statistics"""
        if not self.all_results:
            idaapi.warning("No results available. Run a scan first.")
            return

        # Count by type
        by_type = defaultdict(int)
        total_xrefs = 0

        for item in self.all_results:
            by_type[item["type"]] += 1
            total_xrefs += len(item.get("xrefs", []))

        stats = "Binary Analysis Statistics\n" + "=" * 50 + "\n\n"
        stats += f"Platform: {self.platform_info['processor']}\n"
        stats += f"ARM64: {self.platform_info['is_arm64']}\n"
        stats += f"iOS Binary: {self.platform_info['is_ios']}\n\n"
        stats += f"Total Items Found: {len(self.all_results)}\n"
        stats += f"Total Cross-References: {total_xrefs}\n\n"
        stats += "Items by Type:\n" + "-" * 50 + "\n"

        for type_name, count in sorted(by_type.items(), key=lambda x: -x[1]):
            stats += f"{type_name:25s}: {count:5d}\n"

        idaapi.info(stats)

    def toggle_debug(self):
        """Toggle debug mode"""
        global DEBUG_ENABLED
        DEBUG_ENABLED = not DEBUG_ENABLED
        status = "enabled" if DEBUG_ENABLED else "disabled"
        idaapi.info(f"Debug mode {status}")

    def on_about(self):
        """Show about dialog"""
        about_text = """Swift String Inspector - Enhanced Edition
        
Original Developer: @Keowu
GitHub: github.com/keowu/swiftstringinspector

Enhanced Features:
• Multiple string detection patterns (ADRL/SUB, ADRP/ADD, inline MOV)
• Swift metadata scanning (types, protocols, arrays)
• Objective-C bridge support (selectors, classes)
• Cross-reference tracking
• Export functionality
• Statistics and analytics
• Performance optimizations

Compatible with IDA Pro 9.x"""

        idaapi.info(about_text)

    def Show(self):
        return ida_kernwin.PluginForm.Show(
            self, "Swift String Inspector", options=ida_kernwin.PluginForm.WOPN_PERSIST
        )


class SwiftInspectorPlugin(idaapi.plugmod_t):
    """Plugin module for IDA Pro 9"""

    def __init__(self):
        super().__init__()
        self.form = None

    def run(self, arg):
        if self.form is None:
            self.form = SwiftStringInspectorForm()
            self.form.Show()
        return 0


class PluginEntry(idaapi.plugin_t):
    """Plugin entry point"""

    flags = idaapi.PLUGIN_MULTI
    comment = "Advanced Swift/ObjC string and metadata inspector for iOS binaries"
    wanted_name = "Swift String Inspector Enhanced"
    wanted_hotkey = "Ctrl+Shift+S"

    def init(self):
        # Check if we're on a supported platform
        platform_info = get_platform_info()
        if not platform_info["is_arm64"]:
            print("[SwiftInspector] Warning: Best results on ARM64 binaries")
        return SwiftInspectorPlugin()


def PLUGIN_ENTRY():
    """Required entry point for IDA Pro"""
    return PluginEntry()
