///! JSON (de)serialization of sequences of field elements as hex string.
// TODO: this utils module should not depend on other modules.  Move these
// serialization functions into this module.
use crate::batch_verify::common::native::json::field_element_from_str;
use crate::EccPrimeField;
use serde::{
    de::{SeqAccess, Visitor},
    ser::SerializeSeq,
    Deserializer, Serializer,
};
use std::{fmt, marker::PhantomData};

pub fn serialize<S: Serializer, F: EccPrimeField>(
    v: &[F],
    s: S,
) -> Result<S::Ok, S::Error> {
    let mut seq = s
        .serialize_seq(Some(v.len()))
        .expect("failed to init seq serializer");
    for element in v.iter() {
        let out: String = format!("{element:?}");
        seq.serialize_element(&out)
            .expect("hex serialization failed");
    }
    seq.end()
}

struct FieldElementVecDeserializer<F> {
    __: PhantomData<F>,
}

impl<F> FieldElementVecDeserializer<F> {
    fn new() -> Self {
        Self { __: PhantomData }
    }
}

impl<'de, F> Visitor<'de> for FieldElementVecDeserializer<F>
where
    F: EccPrimeField<Repr = [u8; 32]>,
{
    type Value = Vec<F>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("list of field elements as hex strings.")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut new_obj = Vec::<F>::new();
        while let Some(v) =
            seq.next_element::<String>().expect("seq.next_element")
        {
            new_obj.push(field_element_from_str(&v));
        }

        Ok(new_obj)
    }
}

pub fn deserialize<'de, D: Deserializer<'de>, F>(
    d: D,
) -> Result<Vec<F>, D::Error>
where
    F: EccPrimeField<Repr = [u8; 32]>,
{
    d.deserialize_seq(FieldElementVecDeserializer::new())
}

/// Serialize Vec<[F; 2]> to a hex representation
pub fn serialize_coordinates<F, S>(
    coordinates: &[[F; 2]],
    s: S,
) -> Result<S::Ok, S::Error>
where
    F: EccPrimeField<Repr = [u8; 32]>,
    S: Serializer,
{
    let mut seq = s
        .serialize_seq(Some(coordinates.len()))
        .expect("failed to init seq serializer");
    for element in coordinates.iter() {
        let out: [String; 2] =
            [format!("{:?}", element[0]), format!("{:?}", element[1])];
        seq.serialize_element(&out)
            .expect("hex serialization failed");
    }
    seq.end()
}

struct CoordinateVecDeserializer<F> {
    __: PhantomData<F>,
}

impl<F> CoordinateVecDeserializer<F> {
    fn new() -> Self {
        Self { __: PhantomData }
    }
}

impl<'de, F> Visitor<'de> for CoordinateVecDeserializer<F>
where
    F: EccPrimeField<Repr = [u8; 32]>,
{
    type Value = Vec<[F; 2]>;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("list of coordinate pairs [x, y] as hex strings.")
    }

    fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut new_obj = Vec::<[F; 2]>::new();
        while let Some(v) =
            seq.next_element::<[String; 2]>().expect("seq.next_element")
        {
            new_obj.push([
                field_element_from_str(&v[0]),
                field_element_from_str(&v[1]),
            ]);
        }

        Ok(new_obj)
    }
}

/// Deserialize a `Vec<[F; 2]>` from hex representation.
pub fn deserialize_coordinates<'de, D: Deserializer<'de>, F>(
    d: D,
) -> Result<Vec<[F; 2]>, D::Error>
where
    F: EccPrimeField<Repr = [u8; 32]>,
{
    d.deserialize_seq(CoordinateVecDeserializer::new())
}
