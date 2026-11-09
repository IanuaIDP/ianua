//! Reading a YAML document under a node budget.
//!
//! A YAML alias repeats an anchored value wherever it is named, so a small
//! document can stand for billions of nodes: `b: [*a, *a, ...]` over an
//! anchor `a` of thousands of items. Every node the parser hands over is
//! counted, aliased or not, and the read stops once the budget is spent,
//! before the document has grown large.

use std::cell::Cell;
use std::fmt;

use serde::de::{DeserializeSeed, Error as _, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value};

/// The most nodes one document may hold. A gateway configuration of a
/// thousand routes holds well under this.
pub(super) const NODE_BUDGET: usize = 200_000;

/// The YAML in `bytes` as a JSON value, refused once it holds more than
/// [`NODE_BUDGET`] nodes.
pub(super) fn yaml_within_budget(bytes: &[u8]) -> Result<Value, serde_norway::Error> {
    let left = Cell::new(NODE_BUDGET);
    Budgeted { left: &left }.deserialize(serde_norway::Deserializer::from_slice(bytes))
}

/// Builds one value, spending one node of `left` for it and for each value
/// inside it.
#[derive(Clone, Copy)]
struct Budgeted<'a> {
    left: &'a Cell<usize>,
}

impl Budgeted<'_> {
    /// Spends one node, or refuses once none are left.
    fn spend<E: serde::de::Error>(self) -> Result<(), E> {
        let Some(left) = self.left.get().checked_sub(1) else {
            return Err(E::custom(format!(
                "the document holds more than {NODE_BUDGET} values"
            )));
        };
        self.left.set(left);
        Ok(())
    }
}

impl<'de> DeserializeSeed<'de> for Budgeted<'_> {
    type Value = Value;

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Budgeted<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a YAML value")
    }

    fn visit_bool<E: serde::de::Error>(self, value: bool) -> Result<Value, E> {
        self.spend()?;
        Ok(Value::Bool(value))
    }

    fn visit_i64<E: serde::de::Error>(self, value: i64) -> Result<Value, E> {
        self.spend()?;
        Ok(Value::Number(value.into()))
    }

    fn visit_u64<E: serde::de::Error>(self, value: u64) -> Result<Value, E> {
        self.spend()?;
        Ok(Value::Number(value.into()))
    }

    fn visit_f64<E: serde::de::Error>(self, value: f64) -> Result<Value, E> {
        self.spend()?;
        Number::from_f64(value)
            .map(Value::Number)
            .ok_or_else(|| E::custom("a number that is not finite"))
    }

    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Value, E> {
        self.spend()?;
        Ok(Value::String(value.to_owned()))
    }

    fn visit_string<E: serde::de::Error>(self, value: String) -> Result<Value, E> {
        self.spend()?;
        Ok(Value::String(value))
    }

    fn visit_unit<E: serde::de::Error>(self) -> Result<Value, E> {
        self.spend()?;
        Ok(Value::Null)
    }

    fn visit_none<E: serde::de::Error>(self) -> Result<Value, E> {
        self.visit_unit()
    }

    fn visit_some<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        deserializer.deserialize_any(self)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut items: A) -> Result<Value, A::Error> {
        self.spend()?;
        let mut values = Vec::new();
        while let Some(value) = items.next_element_seed(self)? {
            values.push(value);
        }
        Ok(Value::Array(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut entries: A) -> Result<Value, A::Error> {
        self.spend()?;
        let mut map = Map::new();
        while let Some(key) = entries.next_key_seed(self)? {
            let Value::String(key) = key else {
                return Err(A::Error::custom("a mapping key that is not text"));
            };
            map.insert(key, entries.next_value_seed(self)?);
        }
        Ok(Value::Object(map))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An ordinary document reads as the value it writes.
    #[test]
    fn an_ordinary_document_reads_as_written() {
        let value = yaml_within_budget(b"name: edge\nroutes: [a, b]\n").unwrap();

        assert_eq!(
            value,
            serde_json::json!({"name": "edge", "routes": ["a", "b"]})
        );
    }

    /// YAML aliases that repeat two thousand items two thousand times exceed
    /// the document budget and are rejected.
    #[test]
    fn aliases_that_expand_past_the_budget_are_refused() {
        let bomb = format!(
            "a: &a [{}x]\nb: [{}*a]\n",
            "x,".repeat(2000),
            "*a,".repeat(2000)
        );

        let result = yaml_within_budget(bomb.as_bytes());

        assert!(result.is_err());
    }
}
