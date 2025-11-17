#!/usr/bin/env python3
"""
IDA Pro Automated Driver Analysis Script
Follows the systematic methodology for reverse engineering Windows x64 kernel drivers
to identify loldriver capabilities, particularly process killing functionality.

This script should be run within IDA Pro (headless mode):
    ida64 -A -S"ida_driver_analyzer.py --output results.json" driver.sys
"""

import json
import sys
import os

# IDA Python imports (available when running in IDA)
try:
    import idaapi
    import idc
    import idautils
    import ida_funcs
    import ida_name
    import ida_kernwin
    import ida_bytes
    import ida_segment
    import ida_xref
    IDA_AVAILABLE = True
except ImportError:
    IDA_AVAILABLE = False
    print("[!] Warning: IDA Python modules not available. This script must run in IDA Pro.")


class DriverAnalyzer:
    """Automated Windows driver analyzer using IDA Pro"""

    def __init__(self, output_file=None):
        self.output_file = output_file
        self.results = {
            'driver_name': '',
            'driver_entry': None,
            'device_info': {},
            'dispatch_handlers': {},
            'ioctl_handlers': {},
            'suspicious_functions': [],
            'capabilities': []
        }

        # Dangerous functions to track
        self.dangerous_functions = {
            'ZwOpenProcess': 'process_access',
            'NtOpenProcess': 'process_access',
            'PsLookupProcessByProcessId': 'process_access',
            'ZwTerminateProcess': 'process_termination',
            'NtTerminateProcess': 'process_termination',
            'MmCopyVirtualMemory': 'memory_rw',
            'ZwReadVirtualMemory': 'memory_read',
            'ZwWriteVirtualMemory': 'memory_write',
            'ZwLoadDriver': 'driver_loading',
            'ZwMapViewOfSection': 'memory_mapping',
            'MmMapIoSpace': 'physical_memory',
            'ZwOpenProcessToken': 'token_access',
            'ZwAdjustPrivilegesToken': 'privilege_escalation'
        }

    def log(self, msg):
        """Logging function"""
        print(f"[*] {msg}")
        if IDA_AVAILABLE:
            ida_kernwin.msg(f"{msg}\n")

    def analyze(self):
        """Main analysis orchestration"""
        if not IDA_AVAILABLE:
            self.log("ERROR: Must run within IDA Pro")
            return False

        # Wait for auto-analysis to complete
        self.log("Waiting for IDA auto-analysis to complete...")
        idaapi.auto_wait()

        self.results['driver_name'] = idaapi.get_root_filename()
        self.log(f"Analyzing driver: {self.results['driver_name']}")

        # Step 1: Find DriverEntry
        self.log("Step 1: Locating DriverEntry...")
        driver_entry = self.find_driver_entry()
        if driver_entry:
            self.results['driver_entry'] = hex(driver_entry)
            self.log(f"Found DriverEntry at: {hex(driver_entry)}")
        else:
            self.log("WARNING: Could not locate DriverEntry")

        # Step 2: Follow initialization chain
        if driver_entry:
            self.log("Step 2: Following driver initialization chain...")
            self.analyze_driver_init(driver_entry)

        # Step 3: Find IOCTL handlers
        self.log("Step 3: Locating IOCTL dispatch handlers...")
        self.find_ioctl_handlers()

        # Step 4: Analyze dangerous function usage
        self.log("Step 4: Analyzing dangerous function calls...")
        self.analyze_dangerous_functions()

        # Step 5: Identify capabilities
        self.log("Step 5: Identifying driver capabilities...")
        self.identify_capabilities()

        # Generate report
        self.generate_report()

        return True

    def find_driver_entry(self):
        """Locate the DriverEntry function"""
        # Try common names
        for name in ['DriverEntry', '_DriverEntry', 'DriverEntry@8']:
            addr = idc.get_name_ea_simple(name)
            if addr != idc.BADADDR:
                return addr

        # Try to find by entry point
        entry_points = list(idautils.Entries())
        if entry_points:
            for ordinal, ea, name in entry_points:
                if 'DriverEntry' in name or ordinal == 1:
                    return ea

        # Last resort: look for PDRIVER_OBJECT parameter pattern
        for func_ea in idautils.Functions():
            func_name = idc.get_func_name(func_ea)
            # Check if function has DRIVER_OBJECT parameter pattern
            if self.is_likely_driver_entry(func_ea):
                return func_ea

        return None

    def is_likely_driver_entry(self, func_ea):
        """Heuristic to identify DriverEntry by parameter usage"""
        # Check for IoCreateDevice, RtlInitUnicodeString calls in first few blocks
        func = ida_funcs.get_func(func_ea)
        if not func:
            return False

        # Look for typical DriverEntry patterns
        for head in idautils.Heads(func.start_ea, func.end_ea):
            if idc.print_insn_mnem(head) == 'call':
                target = idc.get_operand_value(head, 0)
                target_name = idc.get_name(target)
                if target_name and 'IoCreateDevice' in target_name:
                    return True

        return False

    def analyze_driver_init(self, driver_entry):
        """Analyze driver initialization to find device name, symbolic link, and dispatch functions"""
        func = ida_funcs.get_func(driver_entry)
        if not func:
            return

        # Look for IoCreateDevice call
        for head in idautils.Heads(func.start_ea, func.end_ea):
            if idc.print_insn_mnem(head) == 'call':
                target = idc.get_operand_value(head, 0)
                target_name = idc.get_name(target)

                if target_name and 'IoCreateDevice' in target_name:
                    # Try to extract device name from before the call
                    device_name = self.extract_unicode_string_before(head)
                    if device_name:
                        self.results['device_info']['device_name'] = device_name

                elif target_name and 'IoCreateSymbolicLink' in target_name:
                    # Extract symbolic link
                    symlink = self.extract_unicode_string_before(head)
                    if symlink:
                        self.results['device_info']['symbolic_link'] = symlink

        # Follow calls to find initialization subroutines
        for head in idautils.Heads(func.start_ea, func.end_ea):
            if idc.print_insn_mnem(head) == 'call':
                target = idc.get_operand_value(head, 0)
                if target != idc.BADADDR and idc.get_segm_name(target) == '.text':
                    # Recursively analyze this function
                    self.analyze_dispatch_setup(target)

    def analyze_dispatch_setup(self, func_ea):
        """Analyze function that sets up MajorFunction dispatch table"""
        func = ida_funcs.get_func(func_ea)
        if not func:
            return

        # Look for assignments to DriverObject->MajorFunction[index]
        for head in idautils.Heads(func.start_ea, func.end_ea):
            disasm = idc.GetDisasm(head)

            # Look for patterns like: mov [rcx+0E0h], rax
            # where offset 0xE0 onwards is the MajorFunction array
            if 'mov' in disasm and '[' in disasm:
                # Try to identify MajorFunction assignment
                if self.is_major_function_assignment(head):
                    handler_addr = self.get_handler_address(head)
                    if handler_addr:
                        irp_type = self.get_irp_type_from_offset(head)
                        handler_name = idc.get_func_name(handler_addr)

                        self.results['dispatch_handlers'][irp_type] = {
                            'address': hex(handler_addr),
                            'name': handler_name
                        }

                        if irp_type == 'IRP_MJ_DEVICE_CONTROL':
                            self.log(f"Found IOCTL handler: {handler_name} at {hex(handler_addr)}")
                            self.analyze_ioctl_dispatcher(handler_addr)

    def is_major_function_assignment(self, ea):
        """Check if instruction assigns to MajorFunction array (offset 0x70+)"""
        # DRIVER_OBJECT.MajorFunction is at offset 0x70
        # Each entry is 8 bytes, so range is 0x70 to 0x170
        op_type = idc.get_operand_type(ea, 0)
        if op_type == idc.o_displ or op_type == idc.o_phrase:
            # Get the offset
            offset = idc.get_operand_value(ea, 0) & 0xFFFFFFFF
            if 0x70 <= offset <= 0x170:
                return True
        return False

    def get_handler_address(self, ea):
        """Extract handler address from assignment instruction"""
        # The handler address is usually in the source operand
        op_type = idc.get_operand_type(ea, 1)

        if op_type == idc.o_imm:
            return idc.get_operand_value(ea, 1)
        elif op_type == idc.o_reg:
            # Need to track back to find what was loaded into the register
            # For now, return None
            return None

        return None

    def get_irp_type_from_offset(self, ea):
        """Determine IRP type from MajorFunction offset"""
        offset = idc.get_operand_value(ea, 0) & 0xFFFFFFFF
        index = (offset - 0x70) // 8

        irp_types = {
            0: 'IRP_MJ_CREATE',
            1: 'IRP_MJ_CREATE_NAMED_PIPE',
            2: 'IRP_MJ_CLOSE',
            3: 'IRP_MJ_READ',
            4: 'IRP_MJ_WRITE',
            14: 'IRP_MJ_DEVICE_CONTROL',
            15: 'IRP_MJ_INTERNAL_DEVICE_CONTROL',
            16: 'IRP_MJ_SHUTDOWN',
        }

        return irp_types.get(index, f'IRP_MJ_UNKNOWN_{index}')

    def analyze_ioctl_dispatcher(self, func_ea):
        """Analyze the IOCTL dispatcher function to find IOCTL codes and handlers"""
        func = ida_funcs.get_func(func_ea)
        if not func:
            return

        self.log(f"Analyzing IOCTL dispatcher at {hex(func_ea)}")

        # Look for switch/case or if-else chains comparing IOCTL codes
        for head in idautils.Heads(func.start_ea, func.end_ea):
            # Look for CMP instructions with large constants (IOCTL codes)
            if idc.print_insn_mnem(head) == 'cmp':
                ioctl_code = idc.get_operand_value(head, 1)

                # IOCTL codes are typically large values
                if ioctl_code > 0x100000:
                    # Find the handler for this IOCTL
                    handler = self.find_handler_after_comparison(head)
                    if handler:
                        self.results['ioctl_handlers'][hex(ioctl_code)] = {
                            'address': hex(handler),
                            'name': idc.get_func_name(handler)
                        }
                        self.log(f"Found IOCTL {hex(ioctl_code)} -> {idc.get_func_name(handler)}")

                        # Analyze this handler for dangerous functions
                        self.analyze_function_for_dangers(handler, ioctl_code)

    def find_handler_after_comparison(self, cmp_ea):
        """Find the function called after an IOCTL comparison"""
        # Look ahead for CALL instruction
        current = cmp_ea
        for _ in range(20):  # Look up to 20 instructions ahead
            current = idc.next_head(current)
            if idc.print_insn_mnem(current) == 'call':
                target = idc.get_operand_value(current, 0)
                if target != idc.BADADDR:
                    return target
            # Stop if we hit a JMP that doesn't match
            if idc.print_insn_mnem(current) in ['jmp', 'ret']:
                break

        return None

    def analyze_function_for_dangers(self, func_ea, context=None):
        """Analyze a function for dangerous API calls"""
        func = ida_funcs.get_func(func_ea)
        if not func:
            return

        dangerous_calls = []

        for head in idautils.Heads(func.start_ea, func.end_ea):
            if idc.print_insn_mnem(head) == 'call':
                target = idc.get_operand_value(head, 0)
                target_name = idc.get_name(target)

                if target_name:
                    for dangerous_func, category in self.dangerous_functions.items():
                        if dangerous_func in target_name:
                            dangerous_calls.append({
                                'function': target_name,
                                'category': category,
                                'address': hex(head),
                                'context': context
                            })
                            self.log(f"    [!] Found dangerous call: {target_name} at {hex(head)}")

        if dangerous_calls:
            self.results['suspicious_functions'].append({
                'function': idc.get_func_name(func_ea),
                'address': hex(func_ea),
                'dangerous_calls': dangerous_calls
            })

    def extract_unicode_string_before(self, ea):
        """Try to extract UNICODE_STRING referenced before this address"""
        # Look backwards for LEA or MOV with string reference
        current = ea
        for _ in range(10):
            current = idc.prev_head(current)
            if idc.print_insn_mnem(current) in ['lea', 'mov']:
                op_value = idc.get_operand_value(current, 1)
                if op_value != idc.BADADDR:
                    # Try to get unicode string
                    string = idc.get_strlit_contents(op_value, -1, idc.STRTYPE_C_16)
                    if string:
                        return string.decode('utf-16le', errors='ignore')

        return None

    def find_ioctl_handlers(self):
        """Find all IOCTL handler functions"""
        # Already done in analyze_dispatch_setup
        pass

    def analyze_dangerous_functions(self):
        """Find all calls to dangerous functions across the binary"""
        self.log("Scanning for dangerous function calls...")

        for func_name, category in self.dangerous_functions.items():
            # Find imports
            for imp_ea in idautils.Names():
                if func_name.lower() in imp_ea[1].lower():
                    # Find all cross-references to this import
                    for xref in idautils.XrefsTo(imp_ea[0]):
                        caller_func = ida_funcs.get_func(xref.frm)
                        if caller_func:
                            self.log(f"Found {func_name} called from {idc.get_func_name(caller_func.start_ea)}")

    def identify_capabilities(self):
        """Identify driver capabilities based on detected patterns"""
        capabilities = set()

        # Check for process killer capability
        has_process_open = False
        has_process_terminate = False

        for susp_func in self.results['suspicious_functions']:
            for call in susp_func['dangerous_calls']:
                if call['category'] == 'process_access':
                    has_process_open = True
                if call['category'] == 'process_termination':
                    has_process_terminate = True

        if has_process_open and has_process_terminate:
            capabilities.add('PROCESS_KILLER')
            self.log("[!] CAPABILITY IDENTIFIED: Process Killer")

        # Check for memory manipulation
        has_memory_rw = any(
            call['category'] in ['memory_rw', 'memory_read', 'memory_write']
            for susp_func in self.results['suspicious_functions']
            for call in susp_func['dangerous_calls']
        )

        if has_process_open and has_memory_rw:
            capabilities.add('MEMORY_MANIPULATION')
            self.log("[!] CAPABILITY IDENTIFIED: Memory Manipulation")

        self.results['capabilities'] = list(capabilities)

    def generate_report(self):
        """Generate and save analysis report"""
        report = {
            'status': 'completed',
            'results': self.results
        }

        # Print summary
        self.log("\n" + "="*60)
        self.log("ANALYSIS SUMMARY")
        self.log("="*60)
        self.log(f"Driver: {self.results['driver_name']}")

        if self.results['device_info']:
            self.log(f"Device: {self.results['device_info'].get('device_name', 'Unknown')}")
            self.log(f"Symlink: {self.results['device_info'].get('symbolic_link', 'Unknown')}")

        self.log(f"\nIOCTL Handlers Found: {len(self.results['ioctl_handlers'])}")
        self.log(f"Suspicious Functions: {len(self.results['suspicious_functions'])}")
        self.log(f"Identified Capabilities: {', '.join(self.results['capabilities']) if self.results['capabilities'] else 'None'}")

        # Save to file
        if self.output_file:
            with open(self.output_file, 'w') as f:
                json.dump(report, f, indent=2)
            self.log(f"\n[+] Report saved to: {self.output_file}")

        return report


def main():
    """Main entry point for IDA script"""
    import argparse

    parser = argparse.ArgumentParser(description='Automated driver analysis for IDA Pro')
    parser.add_argument('--output', '-o', help='Output JSON file', default='analysis_results.json')

    # Parse args from IDA script arguments
    if IDA_AVAILABLE:
        # When running in IDA, args come from idc.ARGV
        args_str = ' '.join(idc.ARGV[1:]) if len(idc.ARGV) > 1 else ''
        if args_str:
            args = parser.parse_args(args_str.split())
        else:
            args = parser.parse_args(['--output', 'analysis_results.json'])
    else:
        args = parser.parse_args()

    analyzer = DriverAnalyzer(output_file=args.output)
    analyzer.analyze()

    if IDA_AVAILABLE:
        # Auto-exit IDA after analysis (for headless mode)
        idc.qexit(0)


if __name__ == '__main__':
    main()
