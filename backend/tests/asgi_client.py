"""Small standard-library ASGI harness; avoids adding an HTTP test dependency."""
import asyncio
import json


def requests(app, bodies, *, path="/search", method="POST"):
    async def run():
        results = []
        async with app.router.lifespan_context(app):
            for body in bodies:
                scope = {'type':'http','asgi':{'version':'3.0'},'http_version':'1.1','method':method,
                         'scheme':'http','path':path,'raw_path':path.encode(),'query_string':b'',
                         'headers':[(b'content-type',b'application/json')],
                         'server':('127.0.0.1',8000),'client':('127.0.0.1',1234),'root_path':''}
                messages = []
                sent = False
                async def receive():
                    nonlocal sent
                    if not sent:
                        sent = True
                        return {'type':'http.request','body':json.dumps(body).encode(),'more_body':False}
                    await asyncio.Event().wait()
                async def send(message):
                    messages.append(message)
                await app(scope,receive,send)
                status = next(m['status'] for m in messages if m['type']=='http.response.start')
                payload = b''.join(m.get('body',b'') for m in messages if m['type']=='http.response.body')
                results.append((status,json.loads(payload)))
        return results
    return asyncio.run(run())
