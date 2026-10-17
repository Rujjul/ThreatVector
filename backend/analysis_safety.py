"""Conservative injection indicators, not a general-purpose attack classifier."""
import re
import unicodedata


INDICATORS = tuple(re.compile(pattern,re.IGNORECASE | re.DOTALL) for pattern in (
    r'\b(?:ignore|disregard|override|forget|bypass)\b.{0,80}\b(?:instructions?|system|developer|policy|rules|guardrails?)\b',
    r'\b(?:reveal|print|send|exfiltrate|disclose|return|output|show)\b.{0,80}\b(?:api[_ -]?key|secrets?|credentials?|system prompt|access token)\b',
    r'<\|(?:im_start|im_end|system|assistant|developer)[^>]*\|>|\[/?INST\]|<<\s*/?SYS\s*>>',
    r'(?:^|\n)\s*(?:system|developer)\s*:',
    r'["\']role["\']\s*:\s*["\'](?:system|developer|tool)["\']',
    r'["\']?(?:tool_calls|function_call)["\']?\s*[:=]',
))


def instruction_like(value):
    if not isinstance(value,str):
        return False
    text = unicodedata.normalize('NFKC',value)
    text = ''.join(c for c in text if unicodedata.category(c) != 'Cf')
    return any(pattern.search(text) for pattern in INDICATORS)


def prompt_chunk(chunk, documents):
    """Explicit projection: no arbitrary provenance/metadata can enter prompts."""
    from .analysis_contract import mitigation_source
    return {**{key:chunk[key] for key in ('chunk_id','document_id','section_id','source_type','text','match_type')},
            'mitigation_source':mitigation_source(chunk,documents)}
