import sys
import requests
from xml.etree import ElementTree

def get_links_for_sitemap(sitemap_url) -> set[str]:
    links = []
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

print(f'Current sitemap {sys.argv[1]}\n')
links = get_links_for_sitemap(sys.argv[1])
links_list = list(links)
print(str(links_list))
