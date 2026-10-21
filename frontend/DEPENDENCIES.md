# Dependency verification — 2026-10-21

The clean-install check surfaced four npm audit findings in the prior build/test lock: one moderate, one high and two critical. The final pinned toolchain is Vite **7.3.7** and Vitest **4.1.11**; application dependencies and React remain unchanged. Transitive patches are frozen in package-lock.json. Node 22.12+ is required; the verified runtime is Node 24.19.0.

The update addresses the audit's dev/test tool findings, including [Vitest mock redirect path traversal](https://github.com/vitest-dev/vitest/security/advisories/GHSA-82fw-gwwq-j7x9), [Tinypool worker-options prototype pollution](https://github.com/tinylibs/tinypool/security/advisories/GHSA-5gmw-xhrv-c9v3), and [Vite Windows path handling](https://github.com/vitejs/vite/security/advisories/GHSA-fx2h-pf6j-xcff). The dependency/lock update is deliberately documented as a stack-default change; no authentication, public hosting or monitoring features were added.

`npm audit --registry https://registry.npmjs.org` reports zero findings for the updated lock at this verification date. This is a registry-advisory snapshot, not a guarantee that all vulnerabilities are known or that every dependency path has been independently security-reviewed. Compatibility results are recorded in Progress.md.
