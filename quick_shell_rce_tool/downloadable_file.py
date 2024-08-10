from dataclasses import dataclass


@dataclass
class DownloadableFile:
    name: str
    size: int
