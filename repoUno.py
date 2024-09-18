#!/usr/bin/env python3
"""
RepoUno: Repository Content Collector for LLMs with Content Deduplication

This script collects the contents of a Git repository into a single JSON file,
optimized for analysis by language models. It includes content deduplication,
size limits, file filtering, and precautions against including sensitive information.

Usage:
    python repouno.py /path/to/repo [options]
"""

import os
import sys
import json
import argparse
import logging
import fnmatch
import time
import hashlib
from typing import Dict, List, Any
from concurrent.futures import ThreadPoolExecutor, as_completed

def setup_logging(verbose: bool):
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(level=level, format='%(asctime)s - %(levelname)s - %(message)s')

def parse_arguments():
    parser = argparse.ArgumentParser(description="RepoUno: Repository Content Collector for LLMs")
    parser.add_argument("repo_path", help="Path to the repository")
    parser.add_argument("-o", "--output", default="repouno_content.json", help="Output file path")
    parser.add_argument("--ignore", nargs="*", default=[
        '.git', '__pycache__', '*.pyc', '*.pyo', '*.pyd', '*.so', '*.dylib', '*.dll', '*.exe', '*.bin',
        '*.pdf', '*.png', '*.jpg', '*.jpeg', '*.gif', '.env', '*.key', '*.pem', '*.p12', '*.pfx',
        'id_rsa', 'id_dsa', '*.log', '*.bak', '*.swp', '*.tmp', '*.temp'
    ], help="Ignore patterns (e.g., '*.pyc', '__pycache__')")
    parser.add_argument("--include", nargs="*", default=['*.py', '*.js', '*.java', '*.md', '*.txt', 'Dockerfile', 'docker-compose.yml', '*.json', '*.yaml', '*.yml'],
                        help="Include patterns (e.g., '*.py', 'src/*')")
    parser.add_argument("--include-ext", nargs="*", help="Include only these file extensions (e.g., '.py', '.md')")
    parser.add_argument("--exclude-ext", nargs="*", help="Exclude these file extensions (e.g., '.log', '.tmp')")
    parser.add_argument("-m", "--max-size", type=int, default=5_000_000, help="Maximum individual file size in bytes to process")
    parser.add_argument("--max-total-size", type=int, default=10_000_000, help="Maximum total size of content to process (in bytes)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose logging")
    return parser.parse_args()

def should_ignore(file_path: str, ignore_patterns: List[str]) -> bool:
    basename = os.path.basename(file_path)
    return any(fnmatch.fnmatch(file_path, pattern) or fnmatch.fnmatch(basename, pattern) for pattern in ignore_patterns)

def should_include(file_path: str, include_patterns: List[str], include_ext: List[str], exclude_ext: List[str]) -> bool:
    basename = os.path.basename(file_path)
    if include_patterns and not any(fnmatch.fnmatch(file_path, pattern) or fnmatch.fnmatch(basename, pattern) for pattern in include_patterns):
        return False
    if include_ext and not any(file_path.endswith(ext) for ext in include_ext):
        return False
    if exclude_ext and any(file_path.endswith(ext) for ext in exclude_ext):
        return False
    return True

def is_binary(file_path: str) -> bool:
    try:
        with open(file_path, 'rb') as f:
            return b'\0' in f.read(1024)
    except Exception as e:
        logging.error(f"Error checking if file is binary {file_path}: {str(e)}")
        return True

def get_language(file_path: str) -> str:
    extension = os.path.splitext(file_path)[1].lower()
    extension_map = {
        '.py': 'python',
        '.js': 'javascript',
        '.java': 'java',
        '.cpp': 'cpp',
        '.c': 'c',
        '.cs': 'csharp',
        '.rb': 'ruby',
        '.go': 'go',
        '.rs': 'rust',
        '.php': 'php',
        '.html': 'html',
        '.css': 'css',
        '.md': 'markdown',
        '.json': 'json',
        '.yaml': 'yaml',
        '.yml': 'yaml',
        '.ipynb': 'jupyter'
    }
    return extension_map.get(extension, 'text')

def extract_summary(content: str) -> str:
    lines = content.strip().splitlines()
    if lines:
        first_line = lines[0].strip()
        if first_line.startswith(('"""', "'''", '#')):
            return first_line.strip('"""').strip("'''").strip('#').strip()
    return ''

def minify_code(content: str, language: str) -> str:
    if language == 'python':
        return '\n'.join(line for line in content.splitlines() if line.strip() and not line.strip().startswith('#'))
    return content

def read_file(file_path: str) -> str:
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return f.read()
    except UnicodeDecodeError:
        try:
            with open(file_path, 'r', encoding='latin-1') as f:
                return f.read()
        except Exception as e:
            logging.error(f"Error reading file {file_path}: {str(e)}")
            return ''
    except Exception as e:
        logging.error(f"Error reading file {file_path}: {str(e)}")
        return ''
def process_file(file_path: str, repo_path: str, max_size: int, args) -> Dict[str, Any]:
    try:
        if os.path.getsize(file_path) > max_size:
            logging.warning(f"Skipping {file_path}: File size exceeds limit")
            return None

        if is_binary(file_path):
            logging.warning(f"Skipping {file_path}: Detected as binary file")
            return None

        relative_path = os.path.relpath(file_path, repo_path)
        
        if any(sensitive_pattern in relative_path.lower() for sensitive_pattern in ['password', 'secret', 'key', 'token', 'credential']):
            logging.warning(f"Skipping {file_path}: File name suggests it may contain sensitive information")
            return None

        content = read_file(file_path)

        if not content.strip():
            logging.warning(f"Skipping {file_path}: File is empty or unreadable")
            return None

        language = get_language(file_path)
        minified_content = minify_code(content, language)
        summary = extract_summary(content)
        content_hash = hashlib.md5(minified_content.encode()).hexdigest()

        return {
            "path": relative_path,
            "language": language,
            "summary": summary,
            "content": minified_content,  # Include the minified content in the output
            "size": os.path.getsize(file_path),
            "last_modified": time.ctime(os.path.getmtime(file_path)),
            "content_hash": content_hash
        }
    except Exception as e:
        logging.exception(f"Exception in processing file {file_path}")
        return None

def get_readme_content(repo_path: str) -> str:
    for readme_name in ['README.md', 'README.txt', 'README']:
        readme_path = os.path.join(repo_path, readme_name)
        if os.path.exists(readme_path):
            try:
                with open(readme_path, 'r', encoding='utf-8') as f:
                    return f.read()
            except Exception as e:
                logging.error(f"Error reading README file {readme_path}: {str(e)}")
    return ''

def process_repository(repo_path: str, args) -> List[Dict[str, Any]]:
    result = []
    total_size = 0
    MAX_TOTAL_SIZE = args.max_total_size
    files_to_process = []

    for root, _, files in os.walk(repo_path):
        for file in files:
            file_path = os.path.join(root, file)
            if should_ignore(file_path, args.ignore):
                continue
            if not should_include(file_path, args.include, args.include_ext, args.exclude_ext):
                continue
            files_to_process.append(file_path)

    files_to_process.sort(key=lambda x: os.path.getsize(x))

    content_hashes = {}

    with ThreadPoolExecutor() as executor:
        futures = {executor.submit(process_file, file_path, repo_path, args.max_size, args): file_path for file_path in files_to_process}
        for future in as_completed(futures):
            file_result = future.result()
            if file_result:
                content_hash = file_result['content_hash']
                if content_hash not in content_hashes:
                    file_size = len(file_result['content'].encode('utf-8'))
                    if total_size + file_size > MAX_TOTAL_SIZE:
                        logging.info(f"Reached maximum total size limit. Stopping processing.")
                        break
                    total_size += file_size
                    content_hashes[content_hash] = file_result
                    result.append(file_result)
                else:
                    content_hashes[content_hash]['duplicate_paths'] = content_hashes[content_hash].get('duplicate_paths', []) + [file_result['path']]
    
    for file_result in result:
        if 'duplicate_paths' in file_result:
            file_result['duplicate_paths'] = list(set(file_result['duplicate_paths']))

    return result

def write_output(data: List[Dict[str, Any]], output_path: str, args):
    try:
        readme_content = get_readme_content(args.repo_path)
        total_lines = sum(len(file['content'].splitlines()) for file in data)
        output_data = {
            "project_overview": readme_content,
            "files": data,
            "file_count": len(data),
            "total_lines": total_lines
        }
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, ensure_ascii=False, indent=2)
        logging.info(f"Analysis complete. Output written to {output_path}")
    except Exception as e:
        logging.error(f"Error writing output to {output_path}: {str(e)}")
        sys.exit(1)

def main():
    args = parse_arguments()
    setup_logging(args.verbose)

    if not os.path.isdir(args.repo_path):
        logging.error(f"The specified path is not a directory: {args.repo_path}")
        sys.exit(1)

    logging.info(f"Analyzing repository: {args.repo_path}")
    logging.info(f"Ignore patterns: {args.ignore}")
    logging.info(f"Include patterns: {args.include}")
    logging.info(f"Maximum individual file size: {args.max_size} bytes")
    logging.info(f"Maximum total content size: {args.max_total_size} bytes")
    logging.warning("Note: This script attempts to skip files that may contain sensitive information, but it's not foolproof. Please review the output before sharing.")

    try:
        data = process_repository(args.repo_path, args)
        write_output(data, args.output, args)
    except Exception as e:
        logging.error(f"An unexpected error occurred: {str(e)}")
        sys.exit(1)

if __name__ == "__main__":
    main()