# NVD bulk/API usage-policy review

Reviewed **2026-10-15 (Asia/Calcutta)**. Status: **policy-content review complete** for the selected API 2.0 and traditional-feed routes. Rendered browser text and measured hashes are referenced in the source manifest. The previous HTTP response was only a JavaScript shell; it has not been rewritten as if it contained the policy.

## API access and bulk acquisition

The official [Getting Started page](https://nvd.nist.gov/developers/start-here) states limits of **5 requests per rolling 30 seconds without a key** and **50 per rolling 30 seconds with a key**. It recommends six seconds between requests, default page sizes, and a single requestor for enterprise use. These are published guidance, not measured application behavior.

For initial acquisition, begin at `startIndex=0`, advance by the returned `resultsPerPage`, and stop when the returned count covers `totalResults` or no records remain. The [API workflow](https://nvd.nist.gov/developers/api-workflows) expressly supports populating a local repository. Record request times, returned counts, selected IDs and raw hashes. Subsequent authorized incremental requests should use modification-date windows and run no more often than once every two hours. This documents NVD guidance; scheduled refresh remains excluded from ThreatVector v1.

The [key-request Terms of Use](https://nvd.nist.gov/developers/request-an-api-key) permit searching, displaying, analyzing and retrieving NVD data. Exceeding or circumventing limits may lead to blocking. Shared proxy/firewall traffic counts toward the shared limit. A key belongs to its original requestor and must not be shared with other individuals or organizations. If a key is configured later, send it in the `apiKey` header, keep it server-side, and never commit or log it. No key was requested, activated or used in this review.

## Traditional bulk feeds

The [Data Feeds page](https://nvd.nist.gov/vuln/data-feeds) prefers APIs but permits feed-based local mirrors. It describes JSON 2.0 yearly files for initial population, then recent/modified feeds containing the previous eight days of changes. Consult each META file before downloading unchanged archives. Its hash refers to the **uncompressed** file; retain compressed-byte hashes separately if used. META-based use is described as reasonably below 200 requests/day, not a separate API quota. No bulk feed was downloaded here.

## Reuse, attribution and derived text

NVD asks applications using the API to display prominently:

> This product uses data from the NVD API but is not endorsed or certified by the NVD.

Identify NVD as the provider of **unmodified source records**; do not imply endorsement. The key-request terms prohibit attributing modified API content as NVD content. ThreatVector's factual summaries are therefore explicitly attributed to **ThreatVector**, with separate references to the original upstream records; they are not presented as NVD-authored descriptions or modified NVD API responses.

[NIST's licensing statement](https://www.nist.gov/open/license) distinguishes employee works from third-party content and includes a worldwide reuse grant to the extent NIST holds foreign copyright, with acknowledgments and modification notices. The [CVE license](https://www.cve.org/legal/termsofuse), now read in the rendered page, permits redistribution and derivatives subject to MITRE's designation and license being retained. These provisions support reuse of the selected CVE/NIST record content with the relevant notices. They do not license every linked vendor report, translation, image or externally owned attachment.

The source manifest classifies the selected unmodified NVD/CVE record text as **Redistributable full text**, conditional on the applicable notices. The curated seed remains original summaries. The separately added raw normalizer fixtures contain two exact NVD API responses, distributed with `notices/NIST-DATA-NOTICE.txt` and `notices/CVE-TERMS.txt`; their descriptions are labeled original source text. A source-reference link is not a claim that NVD authored the separate project summary.

## Implementation boundary

No ingestion client, API-key registration, bulk download, scheduled task or live-provider check was added. Future ingestion still needs bounded retries/backoff, stable selection, source snapshots, rate-limit handling and idempotence tests. Review this policy snapshot again if access methods or published terms change. Page-specific API parameters must also be checked when implementing the normalizer; this review does not certify an implementation that does not yet exist.
