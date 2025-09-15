pub mod b32_split4_formatter;

pub use b32_split4_formatter::B32Split4RecoveryCodeFormatter;

#[derive(Clone, Debug)]
pub enum RecoveryCodeFormat {
    B32Split4,
}

impl RecoveryCodeFormat {
    const B32SPLIT4: &'static str = "b32-split-4";

    fn get_format_list() -> Vec<&'static str> {
        vec![Self::B32SPLIT4]
    }
}

impl TryFrom<String> for RecoveryCodeFormat {
    type Error = String;
    fn try_from(value: String) -> Result<Self, Self::Error> {
        match value.as_str() {
            Self::B32SPLIT4 => Ok(RecoveryCodeFormat::B32Split4),
            _ => {
                let mut errstr =
                    format!("{} is not a valid code format. Valid formats are:", value);
                Self::get_format_list().iter().for_each(|f| {
                    errstr = format!(
                        "{errstr}
                    - {f}"
                    )
                });
                Err(errstr)
            }
        }
    }
}
