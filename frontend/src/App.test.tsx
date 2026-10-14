import { cleanup, render, screen, waitFor } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { afterEach, expect, test, vi } from 'vitest';
import App from './App';
afterEach(() => { cleanup(); vi.restoreAllMocks(); });
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
