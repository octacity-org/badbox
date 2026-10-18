# Rule examples (experimental version 1)

Rules are data, not TypeScript callbacks. The DSL examples use `.badbox` files
written in the Rust-parsed [tiny DSL](../native/tiny-dsl/README.md). That README
is the DSL reference.

Each example is a complete rule pack you can pass to `inspect()` or copy into
`.badbox/`:

- [Rust](rules/rust/excessive-clones.badbox) counts `.clone()` calls per callable.
- [Go](rules/go/excessive-goroutines.badbox) counts `go_statement` nodes, using a
  raw node selector instead of a code pattern.
- [Zig](rules/zig/excessive-as-casts.badbox) counts `@as` casts inside function
  declarations.
- [PowerShell](rules/powershell/excessive-invoke-expression.badbox) counts
  `Invoke-Expression` calls inside functions.

All four use the same ownership and evaluator code. Their thresholds are
illustrative.

## Contract

- Unknown entries, unknown languages or kinds, duplicate rule IDs, unsupported
  versions, and invalid thresholds are rejected. IDs use lowercase
  `namespace/name` with digits and hyphens allowed after the first letter of
  each part.
- The `for` language is one of `bash`, `c`, `cpp`, `csharp`, `css`, `dart`, `elixir`,
  `go`, `haskell`, `hcl`, `html`, `java`, `javascript`, `json`, `kotlin`, `lua`,
  `markdown`, `nix`, `php`, `powershell`, `python`, `ruby`, `rust`, `scala`,
  `solidity`, `swift`, `tsx`, `typescript`, `yaml`, or `zig`. JSX files use `javascript`.
  The scanner's registry maps extensions to statically linked parsers. A rule
  does not select its own parser binary or execute code.
- `find` selects with one source-shaped `code(...)` pattern or one raw
  `node` kind. Patterns currently use ast-grep structural pattern semantics.
  Kind names are Tree-sitter grammar names. These are explicit backend
  dependencies of this experimental format, not a promise of effortless
  backend replacement.
- `group by nearest` assigns each match to its nearest **strict ancestor** of
  the allowed kinds. A match without an owner is ignored. Rules must include
  all boundaries they intend to respect; `callable` includes closures and
  anonymous functions, so their contents do not inflate enclosing counts.
- `when count > n` counts distinct matched node ranges per owner. Owner
  identity is file plus range, never the function name. Overlapping ranges of
  different nodes count separately (e.g. `x.clone().clone()` counts twice).
  The API's optional `threshold` scalar overrides each loaded rule. Zero-count
  owners cannot exceed a nonnegative threshold and are not returned.
- `severity` is `info`, `warning`, or `error`; it is a label, not an exit policy.
  `message` becomes the finding message and `evidence` labels the count.

## Results

`inspect()` returns `languages`, interned `files` and `rules` tables,
`checkedFiles`, `findingCount`, compact `findings`, `truncated`, and
`diagnostics`.
`languages` lists supported languages discovered, even if no loaded rule targets
one. `checkedFiles` counts error-free files actually analyzed with relevant rules.

`findings` is a flat `Uint32Array` with a record width of five:
`fileId`, `ruleId`, `ownerStart`, `ownerEnd`, and exact `observed` count. File
paths occur once in `files`; IDs, thresholds, severity, messages, language, and
evidence labels occur once in `rules`. By default, at most 10,000 records are
returned. `maxFindings` can lower or raise that budget, and zero provides a
count-only result. `truncated` reports omitted records while `findingCount`
remains exact.

Owner offsets are zero-based UTF-8 bytes and end-exclusive. They are not
JavaScript UTF-16 string indices. Line/column presentation is intentionally not
materialized in the check result.

Files and returned findings are sorted deterministically; repeated/overlapping input
paths do not duplicate files. Syntax-error files generate a diagnostic and no
findings. Findings are observations, not assertions that code must change.

## Capability check

The fixture suite proves that Rust clone calls, Go launch statements, PowerShell
`Invoke-Expression` calls, and Zig `@as` calls use the same ownership and
evaluator code, exercises Python end to end, and verifies that all 30 bundled
parsers accept representative source and file extensions.
It also changes a test rule's pattern and threshold in the rule file alone and verifies
the changed evidence through the native API. No language-specific detector
function is involved.

The cancellation-evidence rule and SQL parsing are intentionally not
part of this slice.
