export type Source = 'cve' | 'attack' | 'incident';
export type Index = 'flat' | 'ivf' | 'hnsw';
export type Evidence = { chunk_id: string; document_id: string; source_type: Source; source_id: string | null; title: string; text: string; url: string | null; publication_date: string | null; score: number | null };
export type Claim = { text: string; citation_chunk_ids: string[]; inferred?: boolean };
export type SourceRelationship = { id: string; source_document_id: string; target_document_id: string; relationship_type: string; supporting_chunk_ids: string[]; evidence_text: string | null };
export type Analysis = { source_supported_relationships?: SourceRelationship[]; response_mode?: 'validated_analysis' | 'evidence_only'; generation?: {error: string | null}; status: string; claims: Claim[]; mitigations: Claim[]; related_entities: { id: string; label: string; inferred: boolean; citation_chunk_ids: string[] }[]; uncertainty: string[]; evidence: Evidence[]; timing: { retrieval_ms: number | null; generation_ms: number | null } };
export type Benchmark = { run_id: string; corpus_hash: string; query_set_hash: string; model_revision: string; seed: number; threads: number; hardware: string; versions: Record<string,string>; metrics: { index: Index; ann_recall_at_10: number; relevance_recall_at_10: number; mrr: number; p50_ms: number; p95_ms: number; build_seconds: number; serialized_bytes: number; peak_process_bytes: number }[] };
const base = (import.meta as unknown as { env: Record<string,string> }).env.VITE_API_BASE_URL || 'http://127.0.0.1:8000';
export async function request<T>(path: string, body?: unknown, signal?: AbortSignal): Promise<T> {
  const response = await fetch(`${base}${path}`, { method: body ? 'POST' : 'GET', headers: { 'Content-Type': 'application/json' }, body: body ? JSON.stringify(body) : undefined, signal });
  if (!response.ok) throw new Error(`API request failed (${response.status}). Check that the local service and its data are ready.`);
  return response.json() as Promise<T>;
}
export function validateAnalysis(data: Analysis): Analysis {
  if (!Array.isArray(data.evidence) || !Array.isArray(data.claims) || !Array.isArray(data.mitigations) || !Array.isArray(data.related_entities) || !Array.isArray(data.uncertainty) || !data.timing) throw new Error('The service returned an invalid analysis response.');
  const ids = new Set(data.evidence.map(e => e.chunk_id));
  const cited = [...data.claims, ...data.mitigations, ...data.related_entities];
  if (cited.some(c => !Array.isArray(c.citation_chunk_ids) || c.citation_chunk_ids.length === 0 || c.citation_chunk_ids.some(id => !ids.has(id)))) throw new Error('The service returned untraceable citations. Analysis was not displayed.');
  return data;
}
export function publicUrl(value: string | null): string | undefined {
  if (!value) return undefined;
  try { const url = new URL(value); return ['http:', 'https:'].includes(url.protocol) ? url.href : undefined; } catch { return undefined; }
}
