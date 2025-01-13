#!/usr/bin/env python3
import json
import sys
import argparse
import logging
from typing import Optional, List, Dict, Set

def setup_logging(verbose: bool = False):
    """Configure logging with appropriate level and format."""
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format='%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

def get_result_location(result: dict) -> str:
    """Extract location information from result for logging purposes."""
    locations = result.get('locations', [])
    if locations and 'physicalLocation' in locations[0]:
        physical = locations[0]['physicalLocation']
        if 'artifactLocation' in physical:
            return physical['artifactLocation'].get('uri', 'unknown_location')
    return 'unknown_location'

def build_rules_map(run: dict) -> Dict[str, dict]:
    """Build a mapping of rule IDs to their full rule definitions."""
    rules_map = {}
    if 'tool' in run and 'driver' in run['tool'] and 'rules' in run['tool']['driver']:
        for rule in run['tool']['driver']['rules']:
            if 'id' in rule:
                rules_map[rule['id']] = rule
                logging.debug(f"Adding rule {rule['id']} with severity {rule.get('properties', {}).get('security-severity', 'unknown')}")
    return rules_map

def convert_severity_score(score: float) -> str:
    """Convert a CVSS-style severity score to a severity level."""
    if score >= 9.0: return 'critical'
    elif score >= 7.0: return 'high'
    elif score >= 4.0: return 'medium'
    elif score > 0: return 'low'
    else: return 'note'

def get_severity_from_rule(rule: dict) -> Optional[str]:
    """Extract severity from a rule definition with grype-specific handling."""
    if 'properties' in rule and 'security-severity' in rule['properties']:
        try:
            severity_score = float(rule['properties']['security-severity'])
            severity = convert_severity_score(severity_score)
            logging.debug(f"Converted severity score {severity_score} to {severity}")
            return severity
        except (ValueError, TypeError) as e:
            logging.warning(f"Failed to parse security-severity: {rule['properties']['security-severity']}")
    return None

def cleanup_unused_rules(run: dict, used_rules: Set[str]):
    """Remove rules that aren't referenced by any results."""
    if 'tool' in run and 'driver' in run['tool'] and 'rules' in run['tool']['driver']:
        original_rules = run['tool']['driver']['rules']
        new_rules = [rule for rule in original_rules if rule.get('id') in used_rules]
        rules_removed = len(original_rules) - len(new_rules)

        logging.info(f"Removing {rules_removed} unused rules")
        logging.debug(f"Kept rules: {', '.join(sorted(used_rules))}")

        run['tool']['driver']['rules'] = new_rules
        return rules_removed
    return 0

def filter_sarif(input_file: str, output_file: str, min_severity: Optional[str] = None,
                severity_levels: Optional[List[str]] = None, verbose: bool = False):
    """
    Filter SARIF results based on severity level.

    Args:
        input_file (str): Path to input SARIF file
        output_file (str): Path to output filtered SARIF file
        min_severity (str, optional): Minimum severity level to include
        severity_levels (list, optional): List of specific severity levels to include
        verbose (bool): Enable verbose logging
    """
    setup_logging(verbose)

    # Define severity levels from highest to lowest
    SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'note']

    logging.info(f"Reading SARIF file: {input_file}")
    try:
        with open(input_file, 'r') as f:
            sarif_data = json.load(f)
    except Exception as e:
        logging.error(f"Failed to read input file: {e}")
        exit(1)

    total_results = 0
    kept_results = 0
    total_rules_removed = 0

    # Process each run in the SARIF file
    for run_index, run in enumerate(sarif_data.get('runs', [])):
        logging.info(f"Processing run {run_index + 1}")

        # Build rules map once for the run
        rules_map = build_rules_map(run)
        logging.info(f"Found {len(rules_map)} rules in the file")

        # Log tool information
        tool_info = run.get('tool', {}).get('driver', {})
        if tool_info:
            logging.info(f"Tool: {tool_info.get('name', 'Unknown')} "
                        f"(Version: {tool_info.get('version', 'Unknown')})")

        filtered_results = []
        results = run.get('results', [])
        total_results += len(results)

        # Keep track of which rules are actually used
        used_rules = set()

        for result in results:
            # Get the rule ID from the result
            rule_id = result.get('ruleId')

            if not rule_id:
                logging.warning(f"No ruleId found for result")
                continue

            # Look up the full rule definition
            rule = rules_map.get(rule_id)
            if not rule:
                logging.warning(f"Could not find rule definition for ID: {rule_id}")
                continue

            # Get severity from rule
            severity = get_severity_from_rule(rule)
            if not severity:
                logging.warning(f"Could not determine severity for rule {rule_id}")
                continue

            location = get_result_location(result)
            logging.debug(f"Processing finding - Rule: {rule_id}, Severity: {severity}, Location: {location}")

            # Apply severity filter
            include_result = True
            if min_severity:
                try:
                    min_idx = SEVERITY_ORDER.index(min_severity.lower())
                    current_idx = SEVERITY_ORDER.index(severity.lower())
                    include_result = current_idx <= min_idx
                    if not include_result:
                        logging.debug(f"Skipping result: severity {severity} below minimum {min_severity}")
                except ValueError:
                    include_result = False
                    logging.warning(f"Invalid severity value: {severity}")

            if severity_levels:
                include_result = severity.lower() in [s.lower() for s in severity_levels]
                if not include_result:
                    logging.debug(f"Skipping result: severity {severity} not in requested levels {severity_levels}")

            if include_result:
                filtered_results.append(result)
                kept_results += 1
                used_rules.add(rule_id)
                logging.debug(f"Keeping result: {rule_id} ({severity}) at {location}")

        run['results'] = filtered_results

        # Clean up unused rules
        rules_removed = cleanup_unused_rules(run, used_rules)
        total_rules_removed += rules_removed

    # Log summary statistics
    logging.info(f"Total results processed: {total_results}")
    logging.info(f"Results kept after filtering: {kept_results}")
    logging.info(f"Results filtered out: {total_results - kept_results}")
    logging.info(f"Unused rules removed: {total_rules_removed}")

    # Write filtered results
    logging.info(f"Writing filtered results to: {output_file}")
    try:
        with open(output_file, 'w') as f:
            json.dump(sarif_data, f, indent=2)
        logging.info("Successfully wrote filtered SARIF file")
    except Exception as e:
        logging.error(f"Failed to write output file: {e}")


def main():
    parser = argparse.ArgumentParser(description='Filter SARIF file based on severity levels')
    parser.add_argument('input_file', help='Input SARIF file path')
    parser.add_argument('output_file', help='Output SARIF file path')
    parser.add_argument('--min-severity', choices=['critical', 'high', 'medium', 'low', 'note'],
                        help='Minimum severity level to include')
    parser.add_argument('--severity-levels', nargs='+',
                        choices=['critical', 'high', 'medium', 'low', 'note'],
                        help='Specific severity levels to include')
    parser.add_argument('--verbose', '-v', action='store_true',
                        help='Enable verbose logging')

    args = parser.parse_args()

    filter_sarif(args.input_file, args.output_file,
                args.min_severity, args.severity_levels, args.verbose)

if __name__ == "__main__":
    main()
