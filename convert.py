#!/usr/bin/env python3

import json
import os
import subprocess
import tempfile
from pathlib import Path
from typing import List, Dict
import requests
from urllib.parse import urlparse
import re
import logging

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def download_srs_file(url: str, output_path: str) -> bool:
    """Download SRS file from URL"""
    try:
        logger.info(f"Downloading: {url}")
        response = requests.get(url, timeout=30)
        response.raise_for_status()
        
        with open(output_path, 'wb') as f:
            f.write(response.content)
        return True
    except Exception as e:
        logger.error(f"Failed to download {url}: {e}")
        return False

def decompile_srs_to_json(srs_path: str, json_path: str) -> bool:
    """Decompile SRS file to JSON using sing-box command"""
    try:
        cmd = ['sing-box', 'rule-set', 'decompile', srs_path, '-o', json_path]
        result = subprocess.run(cmd, capture_output=True, text=True)
        
        if result.returncode != 0:
            logger.error(f"Failed to decompile {srs_path}: {result.stderr}")
            return False
        
        logger.info(f"Successfully decompiled {srs_path} to {json_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to run sing-box command: {e}")
        return False

def parse_json_rules(json_path: str) -> Dict:
    """Parse JSON rules file"""
    try:
        with open(json_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data
    except Exception as e:
        logger.error(f"Failed to parse JSON {json_path}: {e}")
        return None

def convert_to_surge_format(json_data: Dict) -> List[str]:
    """Convert sing-box JSON rules to Surge list format"""
    surge_rules = []
    
    if not json_data or 'rules' not in json_data:
        return surge_rules
    
    for rule in json_data['rules']:
        # Process domain rules (can be string or list)
        if 'domain' in rule:
            domains = rule['domain']
            if isinstance(domains, str):
                surge_rules.append(f"DOMAIN,{domains}")
            elif isinstance(domains, list):
                for domain in domains:
                    surge_rules.append(f"DOMAIN,{domain}")
        
        # Process domain_suffix rules (can be string or list)
        if 'domain_suffix' in rule:
            suffixes = rule['domain_suffix']
            if isinstance(suffixes, str):
                surge_rules.append(f"DOMAIN-SUFFIX,{suffixes}")
            elif isinstance(suffixes, list):
                for suffix in suffixes:
                    surge_rules.append(f"DOMAIN-SUFFIX,{suffix}")
        
        # Process domain_keyword rules (can be string or list)
        if 'domain_keyword' in rule:
            keywords = rule['domain_keyword']
            if isinstance(keywords, str):
                surge_rules.append(f"DOMAIN-KEYWORD,{keywords}")
            elif isinstance(keywords, list):
                for keyword in keywords:
                    surge_rules.append(f"DOMAIN-KEYWORD,{keyword}")
        
        # Note: domain_regex is not directly supported in Surge's basic rule format
        # We can add a comment for regex rules
        if 'domain_regex' in rule:
            regexes = rule['domain_regex']
            if isinstance(regexes, str):
                surge_rules.append(f"# Regex rule not directly supported: {regexes}")
            elif isinstance(regexes, list):
                for regex in regexes:
                    surge_rules.append(f"# Regex rule not directly supported: {regex}")
    
    return surge_rules

def save_surge_list(rules: List[str], output_path: str, source_url: str = None):
    """Save rules to Surge list file"""
    try:
        with open(output_path, 'w', encoding='utf-8') as f:
            # Add header comments
            f.write("# Surge Rule Set\n")
            if source_url:
                f.write(f"# Generated from: {source_url}\n")
            f.write(f"# Total rules: {len(rules)}\n")
            f.write("#\n\n")
            
            # Write rules
            for rule in rules:
                f.write(rule + '\n')
        
        logger.info(f"Saved {len(rules)} rules to {output_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to save Surge list: {e}")
        return False

def extract_filename_from_url(url: str) -> str:
    """Extract filename from URL and convert .srs to .list"""
    path = urlparse(url).path
    filename = os.path.basename(path)
    
    # Remove .srs extension and add .list
    if filename.endswith('.srs'):
        filename = filename[:-4] + '.list'
    else:
        filename = filename + '.list'
    
    return filename

def process_single_url(url: str, output_dir: str = "rules"):
    """Process a single SRS URL and convert to Surge list"""
    url = url.strip()
    if not url:
        return
    
    # Create output directory if not exists
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    # Extract filename for output
    output_filename = extract_filename_from_url(url)
    output_path = os.path.join(output_dir, output_filename)
    
    with tempfile.TemporaryDirectory() as tmpdir:
        srs_path = os.path.join(tmpdir, "rule.srs")
        json_path = os.path.join(tmpdir, "rule.json")
        
        # Download SRS file
        if not download_srs_file(url, srs_path):
            return
        
        # Decompile SRS to JSON
        if not decompile_srs_to_json(srs_path, json_path):
            return
        
        # Parse JSON
        json_data = parse_json_rules(json_path)
        if not json_data:
            return
        
        # Convert to Surge format
        surge_rules = convert_to_surge_format(json_data)
        
        # Save Surge list
        save_surge_list(surge_rules, output_path, url)

def main():
    """Main function to process all URLs from Link.txt"""
    link_file = "Link.txt"
    
    if not os.path.exists(link_file):
        logger.error(f"{link_file} not found!")
        return
    
    # Read URLs from Link.txt
    with open(link_file, 'r', encoding='utf-8') as f:
        urls = [line.strip() for line in f if line.strip() and not line.strip().startswith('#')]
    
    if not urls:
        logger.warning("No URLs found in Link.txt")
        return
    
    logger.info(f"Processing {len(urls)} URLs...")
    
    # Process each URL
    for url in urls:
        try:
            process_single_url(url)
        except Exception as e:
            logger.error(f"Failed to process {url}: {e}")
            continue
    
    logger.info("Conversion complete!")

if __name__ == "__main__":
    main()
