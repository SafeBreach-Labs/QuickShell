import yaml
from typing import Dict

from quick_shell_rce_tool.downloadable_file import DownloadableFile
from quick_shell_rce_tool.domain_path import DomainPath, Domain


def parse_popular_files_yaml(filename) -> Dict[DomainPath, list[DownloadableFile]]:
    with open(filename, 'r') as file:
        data = yaml.safe_load(file)

    domain_paths_to_files = {}
    for item in data['domain_paths_to_files']:
        domain_paths = tuple(Domain(domain_str) for domain_str in item['domain_paths'])
        files = tuple(DownloadableFile(file['name'], file['size']) for file in item['files'])
        timeout = item.get('timeout', None)

        domain_paths_to_files[DomainPath(domain_paths, timeout)] = files

    return domain_paths_to_files

