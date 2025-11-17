#!/usr/bin/env python3
"""
Pre-Analysis Import Screener for Windows Drivers
Identifies potential loldriver candidates by checking for suspicious API imports
before committing to full IDA Pro reverse engineering.
"""

import pefile
import sys
import json
import os
from pathlib import Path
from typing import Dict, List, Set, Tuple

# Suspicious API patterns for different loldriver capabilities
SUSPICIOUS_APIS = {
    'process_killer': {
        'required': [
            ['ZwOpenProcess', 'NtOpenProcess', 'PsLookupProcessByProcessId'],
            ['ZwTerminateProcess', 'NtTerminateProcess']
        ],
        'description': 'Process termination capability',
        'severity': 'HIGH'
    },
    'memory_rw': {
        'required': [
            ['ZwOpenProcess', 'NtOpenProcess'],
            ['MmCopyVirtualMemory', 'ZwReadVirtualMemory', 'ZwWriteVirtualMemory']
        ],
        'description': 'Arbitrary memory read/write capability',
        'severity': 'CRITICAL'
    },
    'driver_loader': {
        'required': [
            ['ZwLoadDriver', 'NtLoadDriver'],
        ],
        'description': 'Kernel driver loading capability',
        'severity': 'CRITICAL'
    },
    'registry_manipulation': {
        'required': [
            ['ZwCreateKey', 'ZwSetValueKey', 'NtCreateKey', 'NtSetValueKey'],
        ],
        'description': 'Registry manipulation capability',
        'severity': 'MEDIUM'
    },
    'file_operations': {
        'required': [
            ['ZwCreateFile', 'NtCreateFile'],
            ['ZwWriteFile', 'NtWriteFile', 'ZwDeleteFile']
        ],
        'description': 'File system manipulation capability',
        'severity': 'MEDIUM'
    },
    'callback_removal': {
        'required': [
            ['PsSetCreateProcessNotifyRoutine', 'PsRemoveCreateThreadNotifyRoutine',
             'CmUnRegisterCallback', 'ObUnRegisterCallbacks'],
        ],
        'description': 'Security callback removal capability',
        'severity': 'CRITICAL'
    },
    'physical_memory': {
        'required': [
            ['MmMapIoSpace', 'ZwMapViewOfSection'],
        ],
        'description': 'Physical memory access capability',
        'severity': 'HIGH'
    },
    'token_manipulation': {
        'required': [
            ['ZwOpenProcessToken', 'PsReferencePrimaryToken'],
            ['ZwAdjustPrivilegesToken', 'SeAccessCheck']
        ],
        'description': 'Token/privilege manipulation capability',
        'severity': 'HIGH'
    }
}

# Additional suspicious patterns
BYPASS_INDICATORS = [
    'PatchGuard',
    'KPP',
    'DSE',
    'CI.dll',
    'DriverSignature',
]


class DriverImportAnalyzer:
    def __init__(self, driver_path: str):
        self.driver_path = driver_path
        self.driver_name = os.path.basename(driver_path)
        self.imports = set()
        self.exports = set()
        self.pe = None
        self.suspicious_findings = []

    def analyze(self) -> Dict:
        """Main analysis function"""
        try:
            self.pe = pefile.PE(self.driver_path, fast_load=True)
            self.pe.parse_data_directories(
                directories=[
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_IMPORT'],
                    pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_EXPORT']
                ]
            )

            # Extract imports
            self._extract_imports()

            # Extract exports
            self._extract_exports()

            # Check for suspicious patterns
            findings = self._check_suspicious_patterns()

            # Get file metadata
            metadata = self._get_metadata()

            return {
                'driver_name': self.driver_name,
                'driver_path': self.driver_path,
                'metadata': metadata,
                'imports': sorted(list(self.imports)),
                'exports': sorted(list(self.exports)),
                'findings': findings,
                'recommendation': self._get_recommendation(findings)
            }

        except Exception as e:
            return {
                'driver_name': self.driver_name,
                'driver_path': self.driver_path,
                'error': str(e),
                'recommendation': 'ERROR'
            }
        finally:
            if self.pe:
                self.pe.close()

    def _extract_imports(self):
        """Extract imported functions"""
        if hasattr(self.pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in self.pe.DIRECTORY_ENTRY_IMPORT:
                dll_name = entry.dll.decode('utf-8') if isinstance(entry.dll, bytes) else entry.dll
                for imp in entry.imports:
                    if imp.name:
                        func_name = imp.name.decode('utf-8') if isinstance(imp.name, bytes) else imp.name
                        self.imports.add(func_name)

    def _extract_exports(self):
        """Extract exported functions"""
        if hasattr(self.pe, 'DIRECTORY_ENTRY_EXPORT'):
            for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols:
                if exp.name:
                    func_name = exp.name.decode('utf-8') if isinstance(exp.name, bytes) else exp.name
                    self.exports.add(func_name)

    def _check_suspicious_patterns(self) -> List[Dict]:
        """Check for suspicious API patterns"""
        findings = []

        for pattern_name, pattern_data in SUSPICIOUS_APIS.items():
            matched_groups = []
            total_required = len(pattern_data['required'])

            for api_group in pattern_data['required']:
                # Check if any API from this group is present
                matched = [api for api in api_group if api in self.imports]
                if matched:
                    matched_groups.append(matched)

            # If all required groups have at least one match, it's suspicious
            if len(matched_groups) == total_required:
                findings.append({
                    'pattern': pattern_name,
                    'description': pattern_data['description'],
                    'severity': pattern_data['severity'],
                    'matched_apis': matched_groups,
                    'confidence': 'HIGH'
                })

        return findings

    def _get_metadata(self) -> Dict:
        """Extract PE metadata"""
        try:
            metadata = {
                'machine': pefile.MACHINE_TYPE[self.pe.FILE_HEADER.Machine],
                'timestamp': self.pe.FILE_HEADER.TimeDateStamp,
                'sections': len(self.pe.sections),
                'entry_point': hex(self.pe.OPTIONAL_HEADER.AddressOfEntryPoint),
                'image_base': hex(self.pe.OPTIONAL_HEADER.ImageBase),
            }

            # Check for version info
            if hasattr(self.pe, 'FileInfo'):
                for file_info in self.pe.FileInfo:
                    if hasattr(file_info, 'StringTable'):
                        for st in file_info.StringTable:
                            for entry in st.entries.items():
                                key = entry[0].decode('utf-8') if isinstance(entry[0], bytes) else entry[0]
                                val = entry[1].decode('utf-8') if isinstance(entry[1], bytes) else entry[1]
                                metadata[key] = val

            return metadata
        except:
            return {}

    def _get_recommendation(self, findings: List[Dict]) -> str:
        """Generate recommendation based on findings"""
        if not findings:
            return 'LOW_PRIORITY'

        critical_count = sum(1 for f in findings if f['severity'] == 'CRITICAL')
        high_count = sum(1 for f in findings if f['severity'] == 'HIGH')

        if critical_count >= 2:
            return 'IMMEDIATE_ANALYSIS'
        elif critical_count >= 1 or high_count >= 2:
            return 'HIGH_PRIORITY'
        elif high_count >= 1:
            return 'MEDIUM_PRIORITY'
        else:
            return 'LOW_PRIORITY'


def scan_directory(directory: str, output_file: str = None, verbose: bool = True):
    """Scan a directory of drivers"""
    results = []
    driver_files = list(Path(directory).rglob('*.sys')) + list(Path(directory).rglob('*.dll'))

    if verbose:
        print(f"[*] Found {len(driver_files)} potential driver files")
        print(f"[*] Starting import screening...\n")

    priority_buckets = {
        'IMMEDIATE_ANALYSIS': [],
        'HIGH_PRIORITY': [],
        'MEDIUM_PRIORITY': [],
        'LOW_PRIORITY': [],
        'ERROR': []
    }

    for driver_file in driver_files:
        if verbose:
            print(f"[*] Analyzing: {driver_file.name}")

        analyzer = DriverImportAnalyzer(str(driver_file))
        result = analyzer.analyze()
        results.append(result)

        recommendation = result.get('recommendation', 'ERROR')
        priority_buckets[recommendation].append(result)

        if result.get('findings'):
            if verbose:
                print(f"    [!] SUSPICIOUS: {len(result['findings'])} potential capabilities detected")
                for finding in result['findings']:
                    print(f"        - {finding['description']} ({finding['severity']})")

        if verbose:
            print(f"    [→] Recommendation: {recommendation}\n")

    # Summary
    if verbose:
        print("\n" + "="*80)
        print("SCREENING SUMMARY")
        print("="*80)
        print(f"Total drivers analyzed: {len(results)}")
        print(f"\nPriority Breakdown:")
        for priority, drivers in priority_buckets.items():
            if drivers:
                print(f"  {priority}: {len(drivers)} driver(s)")
                if priority in ['IMMEDIATE_ANALYSIS', 'HIGH_PRIORITY']:
                    for d in drivers:
                        print(f"    - {d['driver_name']}")

        print("\n[*] Drivers marked IMMEDIATE_ANALYSIS or HIGH_PRIORITY should be")
        print("    subjected to full IDA Pro reverse engineering analysis.")

    # Save results
    if output_file:
        with open(output_file, 'w') as f:
            json.dump({
                'summary': {
                    'total_analyzed': len(results),
                    'priority_counts': {k: len(v) for k, v in priority_buckets.items()}
                },
                'priority_buckets': priority_buckets,
                'detailed_results': results
            }, f, indent=2)
        if verbose:
            print(f"\n[+] Results saved to: {output_file}")

    return results, priority_buckets


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description='Pre-screen Windows drivers for suspicious API imports',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Scan a directory of drivers
  python3 import_screener.py /analysis/drivers

  # Scan and save results to JSON
  python3 import_screener.py /analysis/drivers -o results.json

  # Analyze a single driver
  python3 import_screener.py malicious.sys --single
        '''
    )

    parser.add_argument('path', help='Path to driver file or directory')
    parser.add_argument('-o', '--output', help='Output JSON file for results')
    parser.add_argument('--single', action='store_true', help='Analyze single file')
    parser.add_argument('-q', '--quiet', action='store_true', help='Minimal output')

    args = parser.parse_args()

    verbose = not args.quiet

    if args.single:
        analyzer = DriverImportAnalyzer(args.path)
        result = analyzer.analyze()

        if verbose:
            print(json.dumps(result, indent=2))

        if args.output:
            with open(args.output, 'w') as f:
                json.dump(result, f, indent=2)
    else:
        scan_directory(args.path, args.output, verbose)


if __name__ == '__main__':
    main()
