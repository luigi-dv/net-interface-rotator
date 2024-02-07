"""Bland, common-looking host names for the randomized identity."""
import secrets
import string

_PREFIXES = ("MacBook-Air", "MacBook-Pro", "iPhone", "iPad", "DESKTOP-")
_SUFFIX_CHARS = string.ascii_uppercase + string.digits


def random_hostname() -> str:
    name = secrets.choice(_PREFIXES)
    if name == "DESKTOP-":
        name += "".join(secrets.choice(_SUFFIX_CHARS) for _ in range(7))
    return name


def randomized(names: dict[str, str | None]) -> dict[str, str | None]:
    """Replace each set name with a new random one that differs from it."""
    result: dict[str, str | None] = {}
    for key, original in names.items():
        if original is None:
            result[key] = None
            continue
        candidate = random_hostname()
        while candidate.casefold() == original.casefold():
            candidate = random_hostname()
        result[key] = candidate
    return result
