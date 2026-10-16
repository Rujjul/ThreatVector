"""Shared result bounds for native search, retrieval and CLI entry points."""
DEFAULT_TOP_K = 10
MAX_TOP_K = 50


def validate_top_k(value):
    if type(value) is not int or not 1 <= value <= MAX_TOP_K:
        raise ValueError(f'top_k must be an integer from 1 to {MAX_TOP_K}')
    return value
