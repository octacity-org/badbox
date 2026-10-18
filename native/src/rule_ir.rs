//! Backend- and serialization-independent Badbox rule representation.

use crate::model::{Language, Severity};
use std::collections::BTreeMap;

#[derive(Clone, Debug)]
pub struct Rule {
    pub id: String,
    pub language: Language,
    pub summary: String,
    pub severity: Severity,
    pub message: String,
    pub parameters: BTreeMap<String, ParameterValue>,
    pub threshold_parameter: Option<String>,
    pub selection: StructuralSelection,
    pub conditions: Vec<Condition>,
    pub scope: Scope,
    pub aggregation: Aggregation,
    pub threshold: Threshold,
    pub evidence: Evidence,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParameterValue {
    Integer(u32),
    Boolean(bool),
    String(String),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum StructuralSelection {
    Pattern(String),
    /// A pattern parsed inside `context`, matching its node of kind `selector`.
    Contextual {
        context: String,
        selector: String,
    },
    Kind(String),
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Condition {
    Text {
        capture: String,
        operator: TextOperator,
        values: Vec<TextValue>,
    },
    Relation {
        target: RelationTarget,
        relation: Relation,
        require_all: bool,
        selections: Vec<StructuralSelection>,
        shared_captures: Vec<Vec<String>>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TextValue {
    Literal(String),
    /// A rule string parameter, resolved with overrides before compilation.
    Parameter(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum TextOperator {
    Equal,
    NotEqual,
    In,
    NotIn,
    Matches,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RelationTarget {
    Match,
    Group,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Relation {
    Has,
    Lacks,
    Inside,
    NotInside,
    Follows,
    Precedes,
}

#[derive(Clone, Debug)]
pub enum Scope {
    NearestAncestor(Vec<String>),
}

impl Rule {
    /// Parameters whose values text conditions compile into matchers.
    pub fn text_parameters(&self) -> impl Iterator<Item = &str> {
        self.conditions
            .iter()
            .flat_map(|condition| match condition {
                Condition::Text { values, .. } => values.as_slice(),
                Condition::Relation { .. } => &[],
            })
            .filter_map(|value| match value {
                TextValue::Parameter(name) => Some(name.as_str()),
                TextValue::Literal(_) => None,
            })
    }
}

impl Scope {
    pub fn nearest_ancestor_kinds(&self) -> &[String] {
        match self {
            Self::NearestAncestor(kinds) => kinds,
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub enum Aggregation {
    Count,
}

#[derive(Clone, Copy, Debug)]
pub enum Threshold {
    GreaterThan(u32),
}

impl Threshold {
    pub fn greater_than(self) -> u32 {
        match self {
            Self::GreaterThan(value) => value,
        }
    }
}

#[derive(Clone, Debug)]
pub struct Evidence {
    pub subject: String,
}

/// A DSL fixture expectation for a rule declared in the same file.
#[derive(Debug)]
pub struct RuleTest {
    pub rule_id: String,
    pub name: String,
    pub input: String,
    pub findings: u32,
    pub count: Option<u32>,
}
