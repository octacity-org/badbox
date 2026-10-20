import { iterateFindings, type CheckResult } from "../scanner/index.ts";
import type { Baseline } from "../baseline.ts";

export function reportCheck(result: CheckResult, baseline?: Baseline): void {
  for (const finding of iterateFindings(result)) {
    console.log(`${finding.file}:${finding.startLine}:${finding.startColumn}-` +
      `${finding.endLine}:${finding.endColumn} ` +
      `[${finding.rule.severity}] ${finding.rule.id}: ` +
      `${finding.message} ` +
      `(${finding.observed} > ${finding.rule.threshold} ${finding.rule.evidenceSubject})`);
  }
  for (const diagnostic of result.diagnostics) {
    console.error(`${diagnostic.file}: ${diagnostic.message}`);
  }
  const returnedCount = result.findings.length / result.recordWidth;
  const returned = result.truncated ? ` (${returnedCount} returned)` : "";
  const hidden = baseline ? `, ${baseline.hiddenCount} also at ${baseline.ref}` : "";
  console.log(`${result.checkedFiles} files checked, ${result.findingCount} findings${returned}${hidden}, ` +
    `${result.suppressedCount} suppressed, ${result.diagnostics.length} diagnostics`);
}
