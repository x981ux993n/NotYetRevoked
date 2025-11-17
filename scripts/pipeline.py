#!/usr/bin/env python3
"""
Automated Loldriver Analysis Pipeline
Orchestrates the complete workflow from import screening to IDA Pro analysis
"""

import os
import sys
import json
import subprocess
import shutil
from pathlib import Path
from datetime import datetime
import argparse


class AnalysisPipeline:
    """Orchestrates the complete driver analysis pipeline"""

    def __init__(self, drivers_dir, results_dir, ida_path=None, skip_screening=False):
        self.drivers_dir = Path(drivers_dir)
        self.results_dir = Path(results_dir)
        self.ida_path = Path(ida_path) if ida_path else Path('/ida')
        self.skip_screening = skip_screening

        # Create timestamped run directory
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.run_dir = self.results_dir / f'run_{timestamp}'
        self.run_dir.mkdir(parents=True, exist_ok=True)

        self.screening_results = None
        self.analysis_queue = []

    def log(self, msg, level='INFO'):
        """Logging with timestamp"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        print(f"[{timestamp}] [{level}] {msg}")

    def run_pipeline(self):
        """Execute the complete analysis pipeline"""
        self.log("="*80)
        self.log("LOLDRIVER ANALYSIS PIPELINE STARTED")
        self.log("="*80)

        # Step 1: Import Screening
        if not self.skip_screening:
            self.log("PHASE 1: Pre-Analysis Import Screening")
            self.log("-" * 80)
            screening_success = self.run_import_screening()

            if not screening_success:
                self.log("Import screening failed", "ERROR")
                return False

            # Determine which drivers need IDA analysis
            self.prioritize_drivers()
        else:
            self.log("Skipping import screening - analyzing all drivers")
            self.analysis_queue = list(self.drivers_dir.rglob('*.sys'))

        # Step 2: IDA Pro Analysis
        if self.analysis_queue:
            self.log(f"\nPHASE 2: IDA Pro Deep Analysis ({len(self.analysis_queue)} drivers)")
            self.log("-" * 80)
            self.run_ida_analysis()
        else:
            self.log("No drivers queued for IDA analysis")

        # Step 3: Generate Final Report
        self.log("\nPHASE 3: Generating Final Report")
        self.log("-" * 80)
        self.generate_final_report()

        self.log("\n" + "="*80)
        self.log("PIPELINE COMPLETED")
        self.log(f"Results saved to: {self.run_dir}")
        self.log("="*80)

        return True

    def run_import_screening(self):
        """Run the pre-analysis import screening"""
        try:
            screening_output = self.run_dir / 'screening_results.json'

            self.log(f"Scanning drivers in: {self.drivers_dir}")

            cmd = [
                'python3',
                '/analysis/scripts/import_screener.py',
                str(self.drivers_dir),
                '-o', str(screening_output)
            ]

            result = subprocess.run(cmd, capture_output=True, text=True)

            if result.returncode == 0:
                self.log("Import screening completed successfully")

                # Load screening results
                with open(screening_output, 'r') as f:
                    self.screening_results = json.load(f)

                # Print summary
                summary = self.screening_results.get('summary', {})
                self.log(f"  Total drivers scanned: {summary.get('total_analyzed', 0)}")

                priority_counts = summary.get('priority_counts', {})
                for priority, count in priority_counts.items():
                    if count > 0:
                        self.log(f"  {priority}: {count}")

                return True
            else:
                self.log(f"Import screening failed: {result.stderr}", "ERROR")
                return False

        except Exception as e:
            self.log(f"Exception during import screening: {str(e)}", "ERROR")
            return False

    def prioritize_drivers(self):
        """Determine which drivers need IDA analysis based on screening"""
        if not self.screening_results:
            return

        priority_buckets = self.screening_results.get('priority_buckets', {})

        # Queue high and critical priority drivers for IDA analysis
        for priority in ['IMMEDIATE_ANALYSIS', 'HIGH_PRIORITY']:
            drivers = priority_buckets.get(priority, [])
            for driver_info in drivers:
                driver_path = Path(driver_info['driver_path'])
                if driver_path.exists():
                    self.analysis_queue.append({
                        'path': driver_path,
                        'priority': priority,
                        'findings': driver_info.get('findings', [])
                    })

        self.log(f"\nQueued {len(self.analysis_queue)} drivers for IDA Pro analysis")

        for item in self.analysis_queue:
            self.log(f"  - {item['path'].name} ({item['priority']})")

    def run_ida_analysis(self):
        """Run IDA Pro analysis on queued drivers"""
        ida64_binary = self.ida_path / 'ida64'

        if not ida64_binary.exists():
            self.log(f"IDA Pro not found at {ida64_binary}", "ERROR")
            self.log("Please ensure IDA Pro is installed in /ida directory")
            self.log("Skipping IDA analysis...")
            return

        ida_results_dir = self.run_dir / 'ida_analysis'
        ida_results_dir.mkdir(exist_ok=True)

        for idx, item in enumerate(self.analysis_queue, 1):
            driver_path = item['path'] if isinstance(item, dict) else item
            driver_name = driver_path.name

            self.log(f"\n[{idx}/{len(self.analysis_queue)}] Analyzing {driver_name}")

            # Output files
            idb_path = ida_results_dir / f"{driver_name}.i64"
            result_json = ida_results_dir / f"{driver_name}.json"

            try:
                # Run IDA in headless mode
                cmd = [
                    str(ida64_binary),
                    '-A',  # Autonomous mode
                    '-S/analysis/scripts/ida_driver_analyzer.py --output ' + str(result_json),
                    str(driver_path)
                ]

                self.log(f"  Running: {' '.join(cmd)}")

                # Set timeout to prevent hanging
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=600  # 10 minute timeout per driver
                )

                if result.returncode == 0:
                    self.log(f"  ✓ Analysis completed for {driver_name}")

                    # Check if results were generated
                    if result_json.exists():
                        with open(result_json, 'r') as f:
                            analysis = json.load(f)

                        capabilities = analysis.get('results', {}).get('capabilities', [])
                        if capabilities:
                            self.log(f"  [!] CAPABILITIES: {', '.join(capabilities)}", "WARN")
                    else:
                        self.log(f"  Warning: No results file generated", "WARN")
                else:
                    self.log(f"  ✗ Analysis failed (exit code: {result.returncode})", "ERROR")
                    if result.stderr:
                        self.log(f"  Error: {result.stderr[:200]}", "ERROR")

            except subprocess.TimeoutExpired:
                self.log(f"  ✗ Analysis timed out after 10 minutes", "ERROR")
            except Exception as e:
                self.log(f"  ✗ Exception: {str(e)}", "ERROR")

    def generate_final_report(self):
        """Generate consolidated final report"""
        report = {
            'pipeline_run': {
                'timestamp': datetime.now().isoformat(),
                'drivers_directory': str(self.drivers_dir),
                'results_directory': str(self.run_dir)
            },
            'screening_summary': None,
            'ida_analysis_summary': [],
            'high_risk_drivers': []
        }

        # Include screening results
        if self.screening_results:
            report['screening_summary'] = self.screening_results.get('summary')

        # Collect IDA analysis results
        ida_results_dir = self.run_dir / 'ida_analysis'
        if ida_results_dir.exists():
            for result_file in ida_results_dir.glob('*.json'):
                try:
                    with open(result_file, 'r') as f:
                        analysis = json.load(f)

                    driver_results = analysis.get('results', {})
                    capabilities = driver_results.get('capabilities', [])

                    summary_entry = {
                        'driver': driver_results.get('driver_name'),
                        'capabilities': capabilities,
                        'suspicious_functions': len(driver_results.get('suspicious_functions', [])),
                        'ioctl_handlers': len(driver_results.get('ioctl_handlers', {}))
                    }

                    report['ida_analysis_summary'].append(summary_entry)

                    # Flag high-risk drivers
                    if capabilities:
                        report['high_risk_drivers'].append({
                            'driver': driver_results.get('driver_name'),
                            'capabilities': capabilities,
                            'device_info': driver_results.get('device_info', {}),
                            'details_file': str(result_file)
                        })

                except Exception as e:
                    self.log(f"Error processing {result_file}: {str(e)}", "ERROR")

        # Save final report
        final_report_path = self.run_dir / 'final_report.json'
        with open(final_report_path, 'w') as f:
            json.dump(report, f, indent=2)

        # Generate markdown summary
        self.generate_markdown_summary(report)

        self.log(f"Final report saved to: {final_report_path}")

        # Print high-risk summary
        if report['high_risk_drivers']:
            self.log("\n" + "!"*80, "WARN")
            self.log("HIGH-RISK DRIVERS DETECTED", "WARN")
            self.log("!"*80, "WARN")

            for driver in report['high_risk_drivers']:
                self.log(f"\n  Driver: {driver['driver']}", "WARN")
                self.log(f"  Capabilities: {', '.join(driver['capabilities'])}", "WARN")

                device_info = driver.get('device_info', {})
                if device_info:
                    self.log(f"  Device: {device_info.get('device_name', 'Unknown')}", "WARN")
                    self.log(f"  Symlink: {device_info.get('symbolic_link', 'Unknown')}", "WARN")

    def generate_markdown_summary(self, report):
        """Generate a human-readable markdown summary"""
        md_path = self.run_dir / 'REPORT.md'

        with open(md_path, 'w') as f:
            f.write("# Loldriver Analysis Report\n\n")
            f.write(f"**Generated:** {report['pipeline_run']['timestamp']}\n\n")

            # Screening Summary
            if report.get('screening_summary'):
                f.write("## Import Screening Summary\n\n")
                summary = report['screening_summary']
                f.write(f"- **Total Drivers Scanned:** {summary.get('total_analyzed', 0)}\n")

                priority_counts = summary.get('priority_counts', {})
                for priority, count in sorted(priority_counts.items()):
                    if count > 0:
                        f.write(f"- **{priority}:** {count}\n")

                f.write("\n")

            # High-Risk Drivers
            if report.get('high_risk_drivers'):
                f.write("## ⚠️ High-Risk Drivers Detected\n\n")

                for driver in report['high_risk_drivers']:
                    f.write(f"### {driver['driver']}\n\n")
                    f.write(f"**Capabilities:** {', '.join(driver['capabilities'])}\n\n")

                    device_info = driver.get('device_info', {})
                    if device_info:
                        f.write("**Device Information:**\n")
                        f.write(f"- Device Name: `{device_info.get('device_name', 'Unknown')}`\n")
                        f.write(f"- Symbolic Link: `{device_info.get('symbolic_link', 'Unknown')}`\n")

                    f.write(f"\n**Detailed Results:** `{driver['details_file']}`\n\n")
                    f.write("---\n\n")

            # IDA Analysis Summary
            if report.get('ida_analysis_summary'):
                f.write("## IDA Pro Analysis Summary\n\n")
                f.write("| Driver | Capabilities | Suspicious Functions | IOCTL Handlers |\n")
                f.write("|--------|--------------|---------------------|----------------|\n")

                for entry in report['ida_analysis_summary']:
                    caps = ', '.join(entry['capabilities']) if entry['capabilities'] else '-'
                    f.write(f"| {entry['driver']} | {caps} | {entry['suspicious_functions']} | {entry['ioctl_handlers']} |\n")

        self.log(f"Markdown report saved to: {md_path}")


def main():
    parser = argparse.ArgumentParser(
        description='Automated loldriver analysis pipeline',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Full pipeline with screening and IDA analysis
  python3 pipeline.py /analysis/drivers /analysis/results

  # Skip screening and analyze all drivers
  python3 pipeline.py /analysis/drivers /analysis/results --skip-screening

  # Custom IDA path
  python3 pipeline.py /analysis/drivers /analysis/results --ida-path /custom/ida
        '''
    )

    parser.add_argument('drivers_dir', help='Directory containing driver files')
    parser.add_argument('results_dir', help='Directory for analysis results')
    parser.add_argument('--ida-path', default='/ida', help='Path to IDA Pro installation')
    parser.add_argument('--skip-screening', action='store_true',
                        help='Skip import screening and analyze all drivers')

    args = parser.parse_args()

    pipeline = AnalysisPipeline(
        drivers_dir=args.drivers_dir,
        results_dir=args.results_dir,
        ida_path=args.ida_path,
        skip_screening=args.skip_screening
    )

    success = pipeline.run_pipeline()
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
