from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    """One signal. weight > 0 raises risk, weight < 0 is reassuring."""
    code: str
    weight: int
    en: str
    ur: str
    category: str = "url"

    def scoped(self, code_prefix: str, en_prefix: str, ur_prefix: str) -> "Finding":
        return Finding(code_prefix + self.code, self.weight, en_prefix + self.en,
                       ur_prefix + self.ur, self.category)

    @property
    def severity(self) -> str:
        if self.weight >= 25:
            return "high"
        if self.weight >= 10:
            return "medium"
        return "low"
