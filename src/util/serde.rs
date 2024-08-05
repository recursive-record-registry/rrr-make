use std::marker::PhantomData;

use ::serde::{Deserialize, Serialize};
use serde::de::{Unexpected, Visitor};

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum ExplicitOption<T> {
    None(ExplicitNone),
    Some(T),
}

impl<T> From<Option<T>> for ExplicitOption<T> {
    fn from(value: Option<T>) -> Self {
        match value {
            None => Self::default(),
            Some(inner) => Self::Some(inner),
        }
    }
}

impl<T> From<ExplicitOption<T>> for Option<T> {
    fn from(value: ExplicitOption<T>) -> Self {
        match value {
            ExplicitOption::None(_) => None,
            ExplicitOption::Some(inner) => Some(inner),
        }
    }
}

impl<T> Default for ExplicitOption<T> {
    fn default() -> Self {
        Self::None(ExplicitNone::new())
    }
}

impl<T> Clone for ExplicitOption<T>
where
    T: Clone,
{
    fn clone(&self) -> Self {
        match self {
            Self::None(_) => Self::default(),
            Self::Some(inner) => Self::Some(inner.clone()),
        }
    }
}

/// Serializes into/Deserializes from the string `"none"`.
/// Intentionally not constructible, only to be used as part of [`ExplicitOption`].
#[derive(Debug, PartialEq, Eq)]
pub struct ExplicitNone {
    private: PhantomData<()>,
}

impl ExplicitNone {
    const VALUE: &str = "none";
}

impl Serialize for ExplicitNone {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        Self::VALUE.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for ExplicitNone {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct ExplicitNoneVisitor;

        impl<'de> Visitor<'de> for ExplicitNoneVisitor {
            type Value = ExplicitNone;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "the string {:?}", ExplicitNone::VALUE)
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v == ExplicitNone::VALUE {
                    Ok(ExplicitNone::new())
                } else {
                    Err(serde::de::Error::invalid_value(
                        Unexpected::Str(v),
                        &ExplicitNone::VALUE,
                    ))
                }
            }
        }

        deserializer.deserialize_any(ExplicitNoneVisitor)
    }
}

impl ExplicitNone {
    fn new() -> Self {
        Self {
            private: PhantomData,
        }
    }
}

/// Used to disambiguate between an unspecified field and a `null` field.
pub type DoubleOption<T> = Option<ExplicitOption<T>>;

#[cfg(test)]
mod tests {
    use crate::util::serde::DoubleOption;

    use super::ExplicitOption;
    use serde::{Deserialize, Serialize};
    use std::fmt::Debug;

    fn validate_serde_of<T: PartialEq + Debug + Serialize + for<'a> Deserialize<'a>>(
        original: T,
        expected_serialized: Option<&str>,
    ) {
        let serialized = toml::to_string(&original).unwrap();

        dbg!(&original);
        dbg!(&serialized);
        dbg!(&expected_serialized);

        if let Some(expected_serialized) = expected_serialized {
            assert_eq!(serialized, expected_serialized);
        }

        let deserialized = toml::from_str::<T>(&serialized).unwrap();

        assert_eq!(deserialized, original);
    }

    #[test]
    fn explicit_option_toml() {
        #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
        struct RootExplicit<T> {
            optional_field: ExplicitOption<T>,
        }

        #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
        struct RootDouble<T> {
            optional_field: DoubleOption<T>,
        }

        #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
        struct Struct {
            hello: String,
        }

        validate_serde_of(
            RootExplicit {
                optional_field: ExplicitOption::<Struct>::default(),
            },
            Some("optional_field = \"none\"\n"),
        );
        validate_serde_of(
            RootExplicit {
                optional_field: ExplicitOption::Some(Struct {
                    hello: "World".to_string(),
                }),
            },
            None,
        );
        validate_serde_of(
            RootDouble {
                optional_field: DoubleOption::<Struct>::None,
            },
            Some(""),
        );
        validate_serde_of(
            RootDouble {
                optional_field: Some(ExplicitOption::<Struct>::default()),
            },
            Some("optional_field = \"none\"\n"),
        );
        validate_serde_of(
            RootDouble {
                optional_field: Some(ExplicitOption::Some(Struct {
                    hello: "World".to_string(),
                })),
            },
            None,
        );

        #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
        enum Enum {
            Hello(u64),
            World(String),
        }

        validate_serde_of(
            RootExplicit {
                optional_field: ExplicitOption::<Enum>::default(),
            },
            Some("optional_field = \"none\"\n"),
        );
        validate_serde_of(
            RootExplicit {
                optional_field: ExplicitOption::Some(Enum::Hello(0)),
            },
            None,
        );
        validate_serde_of(
            RootExplicit {
                optional_field: ExplicitOption::Some(Enum::World("World".to_string())),
            },
            None,
        );
        validate_serde_of(
            RootDouble {
                optional_field: DoubleOption::<Enum>::None,
            },
            Some(""),
        );
        validate_serde_of(
            RootDouble {
                optional_field: Some(ExplicitOption::<Enum>::default()),
            },
            Some("optional_field = \"none\"\n"),
        );
        validate_serde_of(
            RootDouble {
                optional_field: Some(ExplicitOption::Some(Enum::Hello(0))),
            },
            None,
        );
        validate_serde_of(
            RootDouble {
                optional_field: Some(ExplicitOption::Some(Enum::World("World".to_string()))),
            },
            None,
        );
    }
}
