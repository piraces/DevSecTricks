import os
import re
import subprocess
import sys

def find_markdown_files(directory):
    # Recursively find all markdown files in the directory
    markdown_files = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.endswith(".md"):
                markdown_files.append(os.path.join(root, file))
    return markdown_files

def extract_links(file_path):
    # Extract all URLs from a markdown file
    url_regex = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
    with open(file_path, 'r') as file:
        content = file.read()
        urls = re.findall(url_regex, content)
        return urls

def find_links_in_markdown_files(directory) -> set[str]:
    markdown_files = find_markdown_files(directory)
    links = []
    for file_path in markdown_files:
        urls = extract_links(file_path)
        if urls:
            links.extend(urls)
    return set(links)

def clean_url(url: str) -> str:
    replacements = [(':', ''), (',', ''), ('.', ''), ('\\', '')]
    for old, new in replacements:
        url = url.replace(old, new)
    return url.rstrip(')')

print(f'Current path {sys.argv[1]}')
links = find_links_in_markdown_files(sys.argv[1])
for url in links:
    cleaned_url = clean_url(url.strip())
    print(f'- Archiving {cleaned_url}:')
    result = subprocess.run(['wayback', '--ia', cleaned_url], stdout=subprocess.PIPE)

    # result.stdout contains the output of the command as bytes
    print(result.stdout.decode('utf-8'))
    print('---')

