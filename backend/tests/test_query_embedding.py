"""Deterministic worker-transport tests; never start Torch or model downloads."""
import io
import json
import queue
import threading
from types import SimpleNamespace

import pytest


def encoder(response):
    from backend.query_embedding import QueryEncoder
    client = QueryEncoder.__new__(QueryEncoder)
    state = {'closed':False}
    def terminate():
        state['closed'] = True
    client.process = SimpleNamespace(poll=lambda:0 if state['closed'] else None,
                                     stdin=io.StringIO(), stdout=io.StringIO(),
                                     terminate=terminate,wait=lambda **_:0)
    client.reader = SimpleNamespace(join=lambda **_:None)
    client.responses = queue.Queue()
    client.responses.put(response)
    client.lock = threading.Lock()
    client.timeout = .001
    return client, state


def test_worker_protocol_unicode_vector_and_close():
    np = pytest.importorskip('numpy')
    x = np.zeros((1,384),dtype=np.float32)
    x[0,0] = 1
    client, state = encoder(json.dumps({'vectors':x.tolist()}))
    result = client.encode_query('café vulnerability')
    assert result.dtype == np.float32
    np.testing.assert_array_equal(result,x)
    assert json.loads(client.process.stdin.getvalue()) == {'query':'café vulnerability'}
    client.close()
    assert state['closed'] and client.process.stdout.closed


def test_worker_query_error_preserves_worker():
    pytest.importorskip('numpy')
    client, state = encoder(json.dumps({'error':'Query exceeds the embedding model token limit'}))
    with pytest.raises(ValueError,match='token limit'):
        client.encode_query('long query')
    assert not state['closed']
    client.close()


@pytest.mark.parametrize('response,match', [(None,'stopped unexpectedly'), ('not json','Invalid local'), ('{}','Invalid local')])
def test_bad_worker_responses_fail_closed(response,match):
    pytest.importorskip('numpy')
    client, state = encoder(response)
    with pytest.raises(RuntimeError,match=match):
        client.encode_query('query')
    assert state['closed']


def test_worker_timeout_and_already_stopped_are_bounded():
    pytest.importorskip('numpy')
    client, state = encoder('unused')
    client.responses.get_nowait()
    with pytest.raises(RuntimeError,match='timed out'):
        client.encode_query('query')
    assert state['closed']
    with pytest.raises(RuntimeError,match='stopped'):
        client.encode_query('query')
