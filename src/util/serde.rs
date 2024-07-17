
use ::serde::{Deserialize, Serialize};

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

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct ExplicitNone {
    none: bool,
}

impl ExplicitNone {
    fn new() -> Self {
        Self { none: true }
    }
}

/// Used to disambiguate between an unspecified field and a `null` field.
pub type DoubleOption<T> = Option<ExplicitOption<T>>;

#[cfg(test)]
mod tests {
    use std::fmt::Debug;

    use serde::{Deserialize, Serialize};

    use crate::util::serde::ExplicitNone;

    use super::ExplicitOption;

    fn validate_serde_of<T: PartialEq + Debug + Serialize + for<'a> Deserialize<'a>>(original: T) {
        let serialized = toml::to_string(&original).unwrap();

        dbg!(&original);
        dbg!(&serialized);

        let deserialized = toml::from_str::<T>(&serialized).unwrap();

        assert_eq!(deserialized, original);
    }

    #[test]
    fn explicit_option_toml() {
        validate_serde_of(ExplicitNone::new());
        assert_eq!(
            &toml::to_string(&ExplicitNone::new()).unwrap(),
            "none = true\n"
        );

        #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
        struct Struct {
            hello: String,
        }

        validate_serde_of(ExplicitOption::<Struct>::default());
        validate_serde_of(ExplicitOption::Some(Struct {
            hello: "World".to_string(),
        }));

        #[derive(Debug, Serialize, Deserialize, PartialEq, Eq, Clone)]
        enum Enum {
            Hello(u64),
            World(String),
        }

        validate_serde_of(ExplicitOption::<Enum>::default());
        validate_serde_of(ExplicitOption::Some(Enum::Hello(0)));
        validate_serde_of(ExplicitOption::Some(Enum::World("World".to_string())));
    }
}
