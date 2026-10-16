"""Local query-embedding worker; deliberately imports no FAISS modules."""
import json
import queue
import subprocess
import sys
import threading


class QueryEncoder:
    """Persistent CPU worker isolates Torch's OpenMP runtime from FAISS."""
    def __init__(self, timeout=90):
        flags = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
        self.process = subprocess.Popen([sys.executable, '-u', '-m', 'backend.query_embedding'],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                        text=True, encoding='utf-8', creationflags=flags)
        self.timeout = timeout
        self.responses = queue.Queue()
        self.lock = threading.Lock()
        def read_responses():
            try:
                for line in self.process.stdout:
                    self.responses.put(line)
            finally:
                self.responses.put(None)
        self.reader = threading.Thread(target=read_responses, daemon=True)
        self.reader.start()

    def encode_query(self, query):
        import numpy as np
        with self.lock:
            if self.process.poll() is not None:
                raise RuntimeError('Local embedding worker stopped; reload retrieval service')
            try:
                self.process.stdin.write(json.dumps({'query': query}) + '\n')
                self.process.stdin.flush()
                line = self.responses.get(timeout=self.timeout)
            except (queue.Empty, BrokenPipeError, OSError) as exc:
                self.close()
                raise RuntimeError('Local embedding worker failed or timed out') from exc
            if line is None:
                self.close()
                raise RuntimeError('Local embedding worker stopped unexpectedly')
            try:
                response = json.loads(line)
                if 'error' in response:
                    raise ValueError(response['error'])
                return np.asarray(response['vectors'], dtype=np.float32)
            except (json.JSONDecodeError, KeyError, TypeError) as exc:
                self.close()
                raise RuntimeError('Invalid local embedding worker response') from exc

    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self.reader.join(timeout=5)
        for stream in (self.process.stdin, self.process.stdout):
            if stream is not None:
                stream.close()


def worker():
    # The parent validates its artifact fingerprints; independently verify the
    # same pinned assets here before loading weights. No network/provider calls.
    import torch
    from .embedding import load_model
    torch.set_num_threads(1)
    model = load_model()
    for line in sys.stdin:
        try:
            query = json.loads(line)['query']
            if not isinstance(query, str) or not query.strip() or len(query) > 2000:
                raise ValueError('Query must be nonblank and at most 2,000 characters')
            if len(model.tokenizer.encode(query, truncation=False)) > model.max_seq_length:
                raise ValueError('Query exceeds the embedding model token limit; shorten the question')
            vectors = model.encode([query], batch_size=1, normalize_embeddings=True,
                                   convert_to_numpy=True, show_progress_bar=False)
            response = {'vectors': vectors.tolist()}
        except (ValueError, TypeError, KeyError) as exc:
            response = {'error': str(exc)}
        print(json.dumps(response), flush=True)


if __name__ == '__main__':
    worker()
