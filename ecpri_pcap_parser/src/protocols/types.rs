use nom::{
    error::{ErrorKind as NomErrorKind, ParseError as NomParseError},
    ErrorConvert as NomErrorConvert,
};

pub type Input<'a> = &'a [u8];
pub type Result<'a, T> = nom::IResult<Input<'a>, T, Error<Input<'a>>>;

#[derive(Debug)]
pub struct Error<I> {
    pub errors: Vec<(I, ErrorKind)>,
}

impl<I> NomParseError<I> for Error<I> {
    fn from_error_kind(input: I, kind: NomErrorKind) -> Self {
        let errors = vec![(input, ErrorKind::Nom(kind))];
        Self { errors }
    }

    fn append(input: I, kind: NomErrorKind, mut other: Self) -> Self {
        other.errors.push((input, ErrorKind::Nom(kind)));
        other
    }

    fn add_context<'a>(input: I, ctx: &'a str, mut other: Self) -> Self {
        other.errors.push((input, ErrorKind::Context(ctx.to_string())));
        other
    }
}

#[derive(Debug)]
pub enum ErrorKind {
    Nom(NomErrorKind),
    Context(String)
}
