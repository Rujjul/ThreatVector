"""Server-only OpenAI-compatible Chat Completions transport, no generation policy."""
import json
import math
import os
import socket
from typing import Protocol
from dataclasses import dataclass, field
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


@dataclass(frozen=True)
class ProviderConfig:
    endpoint: str = field(default='', repr=False)
    model: str = ''
    api_key: str = field(default='', repr=False)
    timeout: float = 60.0
    schema_mode: str = 'json_schema'

    @classmethod
    def from_environment(cls):
        try:
            timeout = float(os.environ.get('THREATVECTOR_PROVIDER_TIMEOUT','60'))
        except ValueError:
            raise ValueError('Invalid provider timeout configuration') from None
        return cls(os.environ.get('THREATVECTOR_PROVIDER_ENDPOINT',''),
                   os.environ.get('THREATVECTOR_PROVIDER_MODEL',''),
                   os.environ.get('THREATVECTOR_PROVIDER_KEY',''), timeout,
                   os.environ.get('THREATVECTOR_PROVIDER_SCHEMA_MODE','json_schema'))

    def __post_init__(self):
        if any(not isinstance(v,str) or '\r' in v or '\n' in v for v in (self.endpoint,self.model,self.api_key)):
            raise ValueError('Invalid provider text configuration')
        if type(self.timeout) not in (int,float) or not math.isfinite(self.timeout) or not 0 < self.timeout <= 300:
            raise ValueError('Provider timeout must be between 0 and 300 seconds')
        if self.schema_mode not in ('json_schema','json_object'):
            raise ValueError('Invalid provider schema mode')
        if self.endpoint:
            url = urlsplit(self.endpoint)
            if (url.scheme not in ('https','http') or not url.hostname or url.username or url.password
                    or url.query or url.fragment
                    or (url.scheme == 'http' and url.hostname not in ('localhost','127.0.0.1','::1'))):
                raise ValueError('Provider endpoint must be HTTPS or local HTTP, without credentials or query')


@dataclass(frozen=True)
class ProviderResult:
    status: str
    content: str | None = None
    http_status: int | None = None


class Provider(Protocol):
    def generate(self, messages: list[dict[str,str]], response_schema: dict) -> ProviderResult:
        """Return transport status and raw content; callers validate grounding."""
        ...


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        return None


def post(request, timeout):
    # Never forward authorization to a redirect target. Bound response memory.
    with build_opener(NoRedirect()).open(request, timeout=timeout) as response:
        data = response.read(2_000_001)
        if len(data) > 2_000_000:
            raise ValueError('Provider response too large')
        return json.loads(data)


class OpenAICompatibleProvider:
    def __init__(self, config=None, *, transport=post):
        self.config = config if config is not None else ProviderConfig.from_environment()
        self.transport = transport

    def generate(self, messages, response_schema):
        config = self.config
        if not config.api_key.strip():
            return ProviderResult('missing_credentials')
        if not config.endpoint.strip() or not config.model.strip():
            return ProviderResult('not_configured')
        if (not isinstance(messages,list) or not messages
                or any(not isinstance(m,dict) or set(m) != {'role','content'}
                       or m['role'] not in ('system','user','assistant') or not isinstance(m['content'],str)
                       for m in messages) or not isinstance(response_schema,dict)):
            raise ValueError('Expected text messages and a response schema')
        response_format = ({'type':'json_schema','json_schema':{
            'name':'threatvector_analysis','schema':response_schema,'strict':True}}
            if config.schema_mode == 'json_schema' else {'type':'json_object'})
        payload = {'model':config.model,'messages':messages,'response_format':response_format,'stream':False}
        request = Request(config.endpoint, data=json.dumps(payload).encode('utf-8'),
                          headers={'Authorization':'Bearer '+config.api_key,'Content-Type':'application/json'},method='POST')
        try:
            result = self.transport(request, config.timeout)
            choice = result['choices'][0]
            message = choice['message']
            if not isinstance(message,dict):
                return ProviderResult('invalid_response')
            if message.get('refusal'):
                return ProviderResult('refused')
            if choice.get('finish_reason') != 'stop' or message.get('tool_calls') or message.get('function_call'):
                return ProviderResult('invalid_response')
            content = message['content']
            if not isinstance(content,str) or not content.strip():
                return ProviderResult('invalid_response')
            return ProviderResult('ok',content)
        except HTTPError as exc:
            exc.close()
            return ProviderResult('provider_error',http_status=exc.code)
        except (TimeoutError,socket.timeout):
            return ProviderResult('timeout')
        except URLError as exc:
            return ProviderResult('timeout' if isinstance(exc.reason,TimeoutError) else 'provider_error')
        except OSError:
            return ProviderResult('provider_error')
        except (ValueError,KeyError,IndexError,TypeError):
            return ProviderResult('invalid_response')
