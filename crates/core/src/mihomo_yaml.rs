use serde::de::{DeserializeSeed, Error, MapAccess, SeqAccess, Visitor};
use serde_yaml::Value;
use std::{cell::Cell, fmt, io};

use super::{invalid, MAX_YAML_DEPTH, MAX_YAML_NODES};

pub(super) fn parse(bytes: &[u8]) -> io::Result<Value> {
    let mut documents = serde_yaml::Deserializer::from_slice(bytes);
    let document = documents
        .next()
        .ok_or_else(|| invalid("Empty Mihomo YAML document"))?;
    let remaining = Cell::new(MAX_YAML_NODES);
    let value = Seed {
        remaining: &remaining,
        depth: 0,
    }
    .deserialize(document)
    .map_err(|_| invalid("Malformed Mihomo YAML or nesting/expansion limit exceeded"))?;
    if documents.next().is_some() {
        return Err(invalid(
            "Mihomo configuration must contain exactly one YAML document",
        ));
    }
    Ok(value)
}

#[derive(Clone, Copy)]
struct Seed<'a> {
    remaining: &'a Cell<usize>,
    depth: usize,
}

impl Seed<'_> {
    fn child(self) -> Self {
        Self {
            depth: self.depth + 1,
            ..self
        }
    }
}

impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;

    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        let remaining = self.remaining.get();
        if remaining == 0 || self.depth > MAX_YAML_DEPTH {
            return Err(D::Error::custom("YAML nesting/expansion limit exceeded"));
        }
        self.remaining.set(remaining - 1);
        deserializer.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Seed<'_> {
    type Value = Value;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("bounded YAML data without custom tags")
    }
    fn visit_unit<E: Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E: Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_bool<E: Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_i64<E: Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_u64<E: Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_f64<E: Error>(self, value: f64) -> Result<Value, E> {
        Ok(Value::Number(value.into()))
    }
    fn visit_str<E: Error>(self, value: &str) -> Result<Value, E> {
        Ok(Value::String(value.to_owned()))
    }
    fn visit_string<E: Error>(self, value: String) -> Result<Value, E> {
        Ok(Value::String(value))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(self.child())? {
            values.push(value);
        }
        Ok(Value::Sequence(values))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut mapping: A) -> Result<Value, A::Error> {
        let mut values = serde_yaml::Mapping::new();
        while let Some(key) = mapping.next_key_seed(self.child())? {
            let value = mapping.next_value_seed(self.child())?;
            if values.insert(key, value).is_some() {
                return Err(A::Error::custom("Duplicate YAML mapping key"));
            }
        }
        Ok(Value::Mapping(values))
    }
}
