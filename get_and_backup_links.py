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

print(f'Current path {sys.argv[1]}')
links = find_links_in_markdown_files(sys.argv[1])
for url in links:
    clean_url = url.strip()
    clean_url = clean_url.replace('):', '')
    clean_url = clean_url.replace('),', '')
    clean_url = clean_url.replace(').', '')
    clean_url = clean_url.replace('):', '')
    clean_url = clean_url.replace('\\', '')
    while clean_url.endswith(')'):
        clean_url = clean_url[:-1]
    print(f'- Archiving {clean_url}:')
    # 'ls' is the command, '-l' is an argument to the command
    result = subprocess.run(['wayback', '--ia', '--is', clean_url], stdout=subprocess.PIPE)

    # result.stdout contains the output of the command as bytes
    print(result.stdout.decode('utf-8'))
    print('---')

