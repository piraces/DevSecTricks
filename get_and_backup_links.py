import os
import re
import subprocess
import sys
import requests
from xml.etree import ElementTree

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

def find_links_in_markdown_files_and_sitemap(directory, sitemap_url) -> set[str]:
    markdown_files = find_markdown_files(directory)
    links = []
    for file_path in markdown_files:
        urls = extract_links(file_path)
        if urls:
            links.extend(urls)

    response = requests.get(sitemap_url)
    tree = ElementTree.fromstring(response.content)
    urls_sitemap = [element.text for element in tree.iter('{http://www.sitemaps.org/schemas/sitemap/0.9}loc')]
    links.extend(urls_sitemap)
    return set(links)

def clean_url(url: str) -> str:
    replacements = [('):', ''), ('),', ''), (').', ''), ('\\', '')]
    for old, new in replacements:
        url = url.replace(old, new)
    return url.rstrip(')')

print(f'Current path {sys.argv[1]}')
links = find_links_in_markdown_files_and_sitemap(sys.argv[1], sys.argv[2])
with open("links.txt", 'w') as f:
    for url in links:
        print(f'{clean_url(url.strip())} ')
        f.write(f'{clean_url(url.strip())} ')

print('- Archiving from file:')
result = subprocess.run(['wayback', 'links.txt'], stdout=subprocess.PIPE)

# result.stdout contains the output of the command as bytes
print(result.stdout.decode('utf-8'))

print('---')

