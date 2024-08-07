from dataclasses import dataclass


@dataclass
class Domain:
    domain_str: str

    def __hash__(self):
        return hash((self.domain_str))

    def __eq__(self, other):
        return (self.domain_str) == (other.domain)


@dataclass
class DomainPath:
    domain_order: tuple[Domain]
    sec_delay_between_domains: int = 30

    def __hash__(self):
        return hash((self.domain_order, self.sec_delay_between_domains))

    def __eq__(self, other):
        return (self.domain_order, self.sec_delay_between_domains) == (other.domain_order, other.sec_delay_between_domains)