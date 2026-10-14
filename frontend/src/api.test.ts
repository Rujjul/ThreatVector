import { expect, test } from 'vitest';
import { publicUrl, validateAnalysis } from './api';
import { demoAnalysis } from './demo';
test('untraceable citations are rejected', () => {
  const data = demoAnalysis(['cve'], 'test'); data.claims[0].citation_chunk_ids = ['unknown'];
  expect(() => validateAnalysis(data)).toThrow('untraceable');
});
test('source links allow only HTTP and HTTPS', () => {
  expect(publicUrl('javascript:alert(1)')).toBeUndefined(); expect(publicUrl('https://example.com/report')).toBe('https://example.com/report');
});
