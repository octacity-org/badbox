import { iterateFindings, type CheckResult } from "../scanner/index.ts";
import type { Baseline } from "../baseline.ts";

/** One JSON document for `badbox check --json`. Offsets are UTF-8 bytes; end columns are exclusive. */
export function formatJson(result: CheckResult, baseline?: Baseline): string {
  const findings = [...iterateFindings(result)].map((finding) => ({
    file: finding.file,
    rule: finding.rule.id,
    severity: finding.rule.severity,
    message: finding.message,
    observed: finding.observed,
    threshold: finding.rule.threshold,
    evidence: finding.rule.evidenceSubject,
    start: { line: finding.startLine, column: finding.startColumn, offset: finding.ownerStart },
    end: { line: finding.endLine, column: finding.endColumn, offset: finding.ownerEnd },
  }));
  return JSON.stringify({
    checkedFiles: result.checkedFiles,
    findingCount: result.findingCount,
    suppressedCount: result.suppressedCount,
    truncated: result.truncated,
    ...(baseline ? { baseline } : {}),
    findings,
    diagnostics: result.diagnostics,
  }, null, 2);
}
