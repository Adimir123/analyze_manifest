#!/usr/bin/env python3
import argparse
import json
from bs4 import BeautifulSoup
import itertools
import re
from collections import defaultdict
from dataclasses import dataclass
from typing import List, Dict, Set, Optional

# ANSI color codes
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'
    
    # Component type colors
    ACTIVITY = '\033[38;5;208m'  # Orange
    SERVICE = '\033[38;5;39m'    # Blue
    RECEIVER = '\033[38;5;85m'   # Light Green
    PROVIDER = '\033[38;5;201m'  # Pink

@dataclass
class Component:
    name: str
    type: str
    exported: bool
    permissions: List[str]
    intent_filters: List[Dict]
    risks: List[str]

@dataclass
class AppAnalysis:
    package: str
    components: List[Component]
    deep_links: Dict[str, List[str]]
    vulnerabilities: List[str]
    permissions: Set[str]

def colorize(text: str, color: str) -> str:
    return f"{color}{text}{Colors.RESET}"

def analyze_manifest(manifest_path: str, strings_path: str) -> AppAnalysis:
    # Load string resources
    with open(strings_path, 'r', encoding='utf-8') as f:
        strings_xml = BeautifulSoup(f, 'xml')
        strings = {d['name']: d.text for d in strings_xml.find_all('string', {'name': True})}

    # Parse manifest
    with open(manifest_path, 'r', encoding='utf-8') as f:
        raw_manifest = f.read()
        raw_manifest = re.sub(
            r'"@string/(?P<string_name>[^"]+)"', 
            lambda g: f'"{strings.get(g.group("string_name"), "UNKNOWN_STRING")}"', 
            raw_manifest
        )
        manifest = BeautifulSoup(raw_manifest, 'xml')

    package = manifest.manifest.get('package', 'UNKNOWN_PACKAGE')
    analysis = AppAnalysis(
        package=package,
        components=[],
        deep_links=defaultdict(list),
        vulnerabilities=[],
        permissions=set()
    )

    # Extract all permissions
    analysis.permissions.update(
        p.get('android:name', '') 
        for p in manifest.find_all('uses-permission')
    )

    # Analyze components
    for component in manifest.find_all(['activity', 'service', 'receiver', 'provider']):
        comp_type = component.name
        comp_name = component.get('android:name', '')
        exported = component.get('android:exported', 'false').lower() == 'true'
        permission = component.get('android:permission', '')

        # Component risk analysis
        risks = []
        if exported:
            if not permission:
                risks.append("Exported without permission - may be accessible to other apps")
            if comp_type == 'provider' and 'grantUriPermissions="true"' in str(component):
                risks.append("Provider allows URI permission granting - potential data leakage")

        intent_filters = []
        for intent in component.find_all('intent-filter'):
            actions = [a.get('android:name') for a in intent.find_all('action')]
            categories = [c.get('android:name') for c in intent.find_all('category')]
            data = []
            
            for data_tag in intent.find_all('data'):
                data.append({
                    'scheme': data_tag.get('android:scheme'),
                    'host': data_tag.get('android:host'),
                    'port': data_tag.get('android:port'),
                    'path': data_tag.get('android:path'),
                    'pathPrefix': data_tag.get('android:pathPrefix'),
                    'pathPattern': data_tag.get('android:pathPattern'),
                    'mimeType': data_tag.get('android:mimeType')
                })
            
            intent_filters.append({
                'actions': actions,
                'categories': categories,
                'data': data
            })

        analysis.components.append(Component(
            name=comp_name,
            type=comp_type,
            exported=exported,
            permissions=[permission] if permission else [],
            intent_filters=intent_filters,
            risks=risks
        ))

    # Deep link analysis
    for component in analysis.components:
        for intent in component.intent_filters:
            for data in intent['data']:
                if data['scheme']:
                    uri = f"{data['scheme']}://"
                    if data['host']:
                        uri += data['host']
                        if data['port']:
                            uri += f":{data['port']}"
                        if data['path']:
                            uri += data['path']
                    analysis.deep_links[component.name].append(uri)

    # Vulnerability detection
    if any(c.exported and not c.permissions for c in analysis.components):
        analysis.vulnerabilities.append("Exported components without permission requirements")
    
    if 'android.permission.DANGEROUS' in analysis.permissions:
        analysis.vulnerabilities.append("Uses dangerous permissions")

    return analysis

def print_report(analysis: AppAnalysis, output_format: str = 'text'):
    if output_format == 'json':
        print(json.dumps({
            'package': analysis.package,
            'components': [{
                'name': c.name,
                'type': c.type,
                'exported': c.exported,
                'permissions': c.permissions,
                'risks': c.risks,
                'intent_filters': c.intent_filters
            } for c in analysis.components],
            'deep_links': analysis.deep_links,
            'vulnerabilities': analysis.vulnerabilities,
            'permissions': list(analysis.permissions)
        }, indent=2))
        return

    # Colorful text output
    print(colorize(f"\n📱 Android Manifest Analysis Report", Colors.BOLD + Colors.HEADER))
    print(colorize(f"📦 Package: {analysis.package}", Colors.BOLD + Colors.BLUE))
    
    # Components section
    print(colorize("\n⚙️  Components", Colors.BOLD + Colors.UNDERLINE))
    for comp in analysis.components:
        # Component type specific coloring
        type_color = {
            'activity': Colors.ACTIVITY,
            'service': Colors.SERVICE,
            'receiver': Colors.RECEIVER,
            'provider': Colors.PROVIDER
        }.get(comp.type, Colors.RESET)
        
        print(colorize(f"\n[{comp.type.upper()}]", type_color + Colors.BOLD) + 
              f" {comp.name}")
        
        export_status = colorize("Yes", Colors.YELLOW) if comp.exported else colorize("No", Colors.GREEN)
        print(f"Exported: {export_status}")
        
        if comp.permissions:
            print(f"Permissions: {', '.join(comp.permissions)}")
        
        if comp.risks:
            print(colorize("Risks:", Colors.RED + Colors.BOLD))
            for risk in comp.risks:
                print(f"  {colorize('⚠', Colors.RED)} {risk}")
        
        if comp.intent_filters:
            print(colorize("\nIntent Filters:", Colors.CYAN))
            for i, intent in enumerate(comp.intent_filters, 1):
                print(f"  {i}. Actions: {', '.join(intent['actions'])}")
                if intent['categories']:
                    print(f"     Categories: {', '.join(intent['categories'])}")
                if intent['data']:
                    print("     Data:")
                    for data in intent['data']:
                        print(f"       - {data}")

    # Deep Links section
    print(colorize("\n🔗 Deep Links", Colors.BOLD + Colors.UNDERLINE))
    for component, links in analysis.deep_links.items():
        print(colorize(f"\n{component}:", Colors.BOLD))
        for link in links:
            print(f"  {colorize('➤', Colors.GREEN)} {link}")

    # Security Findings section
    print(colorize("\n🔒 Security Findings", Colors.BOLD + Colors.UNDERLINE))
    if analysis.vulnerabilities:
        for vuln in analysis.vulnerabilities:
            print(f"{colorize('❗', Colors.RED)} {colorize(vuln, Colors.RED)}")
    else:
        print(f"{colorize('✓', Colors.GREEN)} No critical vulnerabilities found")

    # Permissions section
    print(colorize("\n🛡️  Permissions", Colors.BOLD + Colors.UNDERLINE))
    for perm in sorted(analysis.permissions):
        if 'DANGEROUS' in perm or 'SIGNATURE' in perm:
            print(f"{colorize('•', Colors.RED)} {perm}")
        elif 'NORMAL' in perm:
            print(f"{colorize('•', Colors.YELLOW)} {perm}")
        else:
            print(f"{colorize('•', Colors.GREEN)} {perm}")

def main():
    parser = argparse.ArgumentParser(description='Advanced Android Manifest Analyzer')
    parser.add_argument('-m', '--manifest', required=True, help='Path to AndroidManifest.xml')
    parser.add_argument('-s', '--strings', default='res/values/strings.xml',
                       help='Path to strings.xml')
    parser.add_argument('-f', '--format', choices=['text', 'json'], default='text',
                       help='Output format (text/json)')
    args = parser.parse_args()

    try:
        analysis = analyze_manifest(args.manifest, args.strings)
        print_report(analysis, args.format)
    except FileNotFoundError as e:
        print(f"{Colors.RED}Error: {e}{Colors.RESET}")
    except Exception as e:
        print(f"{Colors.RED}An error occurred: {e}{Colors.RESET}")

if __name__ == '__main__':
    main()