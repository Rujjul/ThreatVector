import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, test, vi } from 'vitest';
import App from './App';
import { demoAnalysis } from './demo';
afterEach(() => { cleanup(); vi.restoreAllMocks(); vi.unstubAllGlobals(); });
test('demo investigation opens matching citation evidence and closes by Escape', async () => {
  const user = userEvent.setup(); render(<App/>);
  await user.click(screen.getByRole('button', {name:'Explore the demo'}));
  await user.click(screen.getByRole('button', {name:'Run investigation'}));
  await user.click(screen.getAllByRole('button',{name:'[1]'})[0]);
  expect(screen.getByRole('dialog').textContent).toContain('demo-cve-01');
  await user.keyboard('{Escape}'); expect(screen.queryByRole('dialog')).toBeNull();
});
test('source filters constrain demo evidence and unsupported questions are empty', async () => {
  const user = userEvent.setup(); render(<App/>);
  await user.click(screen.getByRole('button',{name:'Explore the demo'}));
  await user.click(screen.getByLabelText('ATT&CK techniques')); await user.click(screen.getByLabelText('Incident reports'));
  await user.click(screen.getByRole('button',{name:'Run investigation'}));
  expect(screen.getByText(/Retrieved evidence/).textContent).toContain('1');
  const question = screen.getByLabelText('Your question'); await user.clear(question); await user.type(question,'unsupported weather question');
  await user.click(screen.getByRole('button',{name:'Run investigation'})); expect(screen.getByText('No supporting evidence')).toBeTruthy();
});
test('live API failure stays visible and never substitutes demo evidence', async () => {
  vi.spyOn(globalThis,'fetch').mockRejectedValue(new Error('Local service offline'));
  const user = userEvent.setup(); render(<App/>); await user.click(screen.getByRole('button',{name:'Explore the demo'}));
  await user.selectOptions(screen.getByLabelText('Data mode'),'live');
  await user.click(screen.getByRole('button',{name:'Run investigation'}));
  await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('Local service offline'));
  expect(screen.queryByText('Remote access service · example vulnerability')).toBeNull();
});
test('benchmark demo does not invent measured results', async () => {
  const user = userEvent.setup(); render(<App/>); await user.click(screen.getByRole('button',{name:'Benchmarks'}));
  expect(screen.getByText('No measured benchmark runs yet.')).toBeTruthy();
});

test('live analysis opens matching document and separates explicit assertions', async () => {
  const data = demoAnalysis(['cve'], 'test'); data.status='ok';
  const hit=data.evidence[0];
  const response={...data,source_supported_relationships:[{id:'fixture-relation',source_document_id:hit.document_id,target_document_id:'attack:T1190',relationship_type:'mentions_identifier',supporting_chunk_ids:[hit.chunk_id],evidence_text:'Fixture mention only.'}]};
  const fetch=vi.spyOn(globalThis,'fetch').mockImplementation(async input => new Response(JSON.stringify(String(input).endsWith('/health') ? {status:'retrieval_ready'} : String(input).includes('/documents/') ? {chunks:[hit]} : response),{status:200}));
  const user=userEvent.setup();render(<App/>);
  await user.click(screen.getByRole('button',{name:'Explore the demo'}));
  await user.selectOptions(screen.getByLabelText('Data mode'),'live');
  await user.click(screen.getByRole('button',{name:'Run investigation'}));
  await screen.findByText('Explicit source relationships');
  expect(screen.getByText(/Similarity does not establish exploitation/)).toBeTruthy();
  await user.click(screen.getAllByRole('button',{name:'[1]'})[0]);
  await waitFor(() => expect(fetch.mock.calls.some(([url]) => String(url).includes(encodeURIComponent(hit.document_id)))).toBe(true));
  expect(screen.getByRole('dialog').textContent).toContain(hit.chunk_id);
  expect(screen.getByRole('dialog').textContent).toContain(hit.text);
});

test('analysis provider failure preserves live evidence and correct unscored label', async () => {
  const data=demoAnalysis(['cve'],'test');
  const response={...data,status:'generation_error',claims:[],mitigations:[],related_entities:[],uncertainty:['An explanation is unavailable; only stored evidence is shown.']};
  vi.spyOn(globalThis,'fetch').mockImplementation(async input => new Response(JSON.stringify(String(input).endsWith('/health') ? {status:'retrieval_ready'} : response),{status:200}));
  const user=userEvent.setup();render(<App/>);
  await user.click(screen.getByRole('button',{name:'Explore the demo'}));
  await user.selectOptions(screen.getByLabelText('Data mode'),'live');
  await user.click(screen.getByRole('button',{name:'Run investigation'}));
  await screen.findByText('An explanation is unavailable; only stored evidence is shown.');
  expect(screen.getByText('Source evidence · unscored')).toBeTruthy();
  expect(screen.queryByText('Demo · unscored')).toBeNull();
});


test('benchmark table displays the saved measurements returned by API without recomputing them', async () => {
  vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} });
  const metrics=['flat','ivf','hnsw'].map((index,i)=>({index,ann_recall_at_10:1-i*.1,relevance_recall_at_10:.7,mrr:.6,p50_ms:1.234+i,p95_ms:2.345+i,build_seconds:3.456+i,serialized_bytes:123456+i,peak_process_bytes:7654321+i}));
  const run={run_id:'fixture-export',corpus_hash:'a'.repeat(64),query_set_hash:'b'.repeat(64),model_revision:'c'.repeat(40),seed:42,threads:1,hardware:'fixture hardware',versions:{test:'fixture'},metrics};
  vi.spyOn(globalThis,'fetch').mockImplementation(async input=>new Response(JSON.stringify(String(input).endsWith('/health') ? {status:'retrieval_ready'} : {runs:[run],errors:[]} ),{status:200}));
  const user=userEvent.setup();render(<App/>);
  await user.click(screen.getByRole('button',{name:'Explore the demo'}));
  await user.selectOptions(screen.getByLabelText('Data mode'),'live');
  await user.click(screen.getByRole('button',{name:'Benchmarks'}));
  await screen.findByRole('table');
  expect(screen.getByRole('cell',{name:'1.234'})).toBeTruthy();
  expect(screen.getByRole('cell',{name:'123456'})).toBeTruthy();
  expect(screen.getByText('fixture hardware')).toBeTruthy();
  expect(screen.getByDisplayValue('fixture-export')).toBeTruthy();
});
