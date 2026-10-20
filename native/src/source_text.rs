//! Line/column positions and inline suppression comments, computed from source text.

use crate::model::Position;
use std::collections::HashMap;

const IGNORE_MARKER: &str = "badbox-ignore";

/// Byte offsets of every line start in one source file.
pub struct LineIndex {
    starts: Vec<usize>,
}

impl LineIndex {
    pub fn new(source: &str) -> Self {
        let mut starts = vec![0];
        starts.extend(
            source
                .bytes()
                .enumerate()
                .filter(|(_, byte)| *byte == b'\n')
                .map(|(index, _)| index + 1),
        );
        Self { starts }
    }

    /// 1-based line of a byte offset.
    pub fn line(&self, offset: usize) -> usize {
        self.starts.partition_point(|start| *start <= offset)
    }

    /// 1-based line and code-point column of a byte offset.
    pub fn position(&self, source: &str, offset: usize) -> Position {
        let line = self.line(offset);
        let start = self.starts[line - 1];
        let end = offset.min(source.len());
        // Count UTF-8 lead bytes so an offset inside a code point cannot panic.
        let column = source.as_bytes()[start.min(end)..end]
            .iter()
            .filter(|byte| (**byte & 0xc0) != 0x80)
            .count()
            + 1;
        Position {
            line: saturating_u32(line),
            column: saturating_u32(column),
        }
    }
}

fn saturating_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// Rule IDs named by `badbox-ignore` comments, keyed by the 1-based line they apply to: the line
/// directly below the comment.
#[derive(Default)]
pub struct Suppressions {
    by_line: HashMap<usize, Vec<String>>,
}

impl Suppressions {
    pub fn parse(source: &str) -> Self {
        let mut by_line: HashMap<usize, Vec<String>> = HashMap::new();
        if !source.contains(IGNORE_MARKER) {
            return Self { by_line };
        }
        for (index, line) in source.lines().enumerate() {
            let mut rest = line;
            while let Some(found) = rest.find(IGNORE_MARKER) {
                rest = &rest[found + IGNORE_MARKER.len()..];
                let ids = rule_ids(rest);
                if !ids.is_empty() {
                    // The comment is on line index + 1, so it covers line index + 2.
                    by_line.entry(index + 2).or_default().extend(ids);
                }
            }
        }
        Self { by_line }
    }

    pub fn is_empty(&self) -> bool {
        self.by_line.is_empty()
    }

    pub fn covers(&self, line: usize, rule_id: &str) -> bool {
        self.by_line
            .get(&line)
            .is_some_and(|ids| ids.iter().any(|id| id == rule_id))
    }
}

/// Rule IDs after the marker, separated by spaces or commas, up to the first other character.
fn rule_ids(text: &str) -> Vec<String> {
    // The marker must be followed by whitespace, so `badbox-ignored` is not a suppression.
    if !text.starts_with([' ', '\t']) {
        return Vec::new();
    }
    let is_id = |character: char| {
        character.is_ascii_alphanumeric() || matches!(character, '/' | '-' | '_' | '.')
    };
    let mut ids = Vec::new();
    let mut rest = text;
    loop {
        rest = rest.trim_start_matches([' ', '\t', ',']);
        let length = rest
            .find(|character| !is_id(character))
            .unwrap_or(rest.len());
        if length == 0 {
            return ids;
        }
        ids.push(rest[..length].to_owned());
        rest = &rest[length..];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn positions_use_one_based_lines_and_code_point_columns() {
        let source = "ab\nçé x\n\nlast";
        let lines = LineIndex::new(source);
        assert_eq!(lines.position(source, 0), Position { line: 1, column: 1 });
        assert_eq!(lines.position(source, 2), Position { line: 1, column: 3 });
        assert_eq!(lines.position(source, 3), Position { line: 2, column: 1 });
        // "çé " is five bytes but three code points.
        assert_eq!(lines.position(source, 8), Position { line: 2, column: 4 });
        assert_eq!(lines.position(source, 11), Position { line: 4, column: 1 });
        assert_eq!(
            lines.position(source, source.len()),
            Position { line: 4, column: 5 }
        );
    }

    #[test]
    fn suppressions_cover_the_next_line_for_listed_rules() {
        let source = "// badbox-ignore rust/a, rust/b\nfn f() {}\n# badbox-ignore go/c */\n";
        let suppressions = Suppressions::parse(source);
        assert!(suppressions.covers(2, "rust/a"));
        assert!(suppressions.covers(2, "rust/b"));
        assert!(!suppressions.covers(1, "rust/a"));
        assert!(!suppressions.covers(2, "go/c"));
        assert!(suppressions.covers(4, "go/c"));
    }

    #[test]
    fn suppressions_require_at_least_one_rule_id() {
        for source in [
            "// badbox-ignore\nx",
            "// badbox-ignored rust/a\nx",
            "// badbox-ignore */\nx",
        ] {
            assert!(Suppressions::parse(source).is_empty(), "{source}");
        }
    }
}
