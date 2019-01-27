use clap::{Error as ClapError, Arg, ArgMatches, App};
use openssl::x509::{X509NameBuilder, X509Name, X509ReqBuilder};
use openssl::error::ErrorStack as SslError;
use openssl::asn1::Asn1Time;

use openssl::stack::Stack;
use openssl::x509::X509Extension;
use openssl::x509::extension::{SubjectAlternativeName};
use std::num::ParseIntError;
use openssl::nid::Nid;

#[derive(Debug)]
pub enum ParseError {
    Arg(ClapError),
    Ssl(SslError),
    ParseInt(ParseIntError),
    Name(String),
}

impl From<&str> for ParseError {
    fn from(x: &str) -> Self {
        ParseError::Name(x.to_string())
    }
}

impl From<ClapError> for ParseError {
    fn from(x: ClapError) -> Self {
        ParseError::Arg(x)
    }
}

impl From<SslError> for ParseError {
    fn from(x: SslError) -> Self {
        ParseError::Ssl(x)
    }
}

impl From<ParseIntError> for ParseError {
    fn from(x: ParseIntError) -> Self {
        ParseError::ParseInt(x)
    }
}

pub fn parser_name_builder<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
    app
        .arg(
            Arg::with_name("cn")
                .short("N")
                .long("common-name")
                .value_name("common name")
                .required(true)
        )
        .arg(
            Arg::with_name("st")
                .short("S")
                .long("state")
                .value_name("state")
                .required(false)
        )
        .arg(
            Arg::with_name("or")
                .short("O")
                .long("organisation")
                .value_name("organisation")
                .required(false)
        )
        .arg(
            Arg::with_name("co")
                .short("C")
                .long("country")
                .value_name("country")
                .required(false)
        )
}

pub fn parser_not_after_before<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
    app
        .arg(
            Arg::with_name("before")
                .long("before")
                .value_name("before")
                .default_value("0")
                .required(true)
        )
        .arg(
            Arg::with_name("after")
                .long("after")
                .value_name("after")
                .default_value("3650")
                .required(true)
        )
}

pub enum CsrExt {
    Client,
    Server,
    SanDns(Vec<String>),
}

pub fn parser_csr_extensions<'a, 'b>(app: App<'a, 'b>) -> App<'a, 'b> {
    app
        .arg(
            Arg::with_name("ext_server")
                .long("ext-server")
                .value_name("Enable the server extensions")
                .takes_value(false)
        )
        .arg(
            Arg::with_name("ext_client")
                .long("ext-client")
                .conflicts_with("ext_server")
                .value_name("Enable the client extensions")
                .takes_value(false)
        )
        .arg(
            Arg::with_name("san_dnss")
                .long("san-dns")
                .value_name("Specify SubjectAltName DNS records")
                .number_of_values(1)
                .multiple(true)
        )
}

pub fn matches_name_builder(matches: &ArgMatches) -> Result<X509Name, ParseError> {
    let mut x509_name = X509NameBuilder::new()?;

    let cn = matches.value_of("cn").ok_or("common name")?;

    x509_name.append_entry_by_text("CN", cn)?;

    if let Some(x) = matches.value_of("st") {
        x509_name.append_entry_by_text("ST", x)?;
    }

    if let Some(x) = matches.value_of("or") {
        x509_name.append_entry_by_text("O", x)?;
    }

    if let Some(x) = matches.value_of("co") {
        x509_name.append_entry_by_text("C", x)?;
    }

    Ok(x509_name.build())
}

pub fn matches_not_after_before(matches: &ArgMatches) -> Result<(Option<Asn1Time>, Option<Asn1Time>), ParseError> {
    let before = if let Some(x) = matches.value_of("before") {
        Some(Asn1Time::days_from_now(x.parse::<u32>().map_err(|_| "before")?)?)
    } else {
        None
    };

    let after = if let Some(x) = matches.value_of("after") {
        Some(Asn1Time::days_from_now(x.parse::<u32>().map_err(|_| "after")?)?)
    } else {
        None
    };

    Ok((before, after))
}

pub fn matches_csr_extensions(matches: &ArgMatches) -> Result<Vec<CsrExt>, ParseError> {
    let mut res = Vec::<CsrExt>::default();

    if matches.is_present("ext_server") {
        res.push(CsrExt::Server);
    }

    if matches.is_present("ext_client") {
        res.push(CsrExt::Client);
    }

    if let Some(sans) = matches.values_of("san_dnss") {
        let mut r = Vec::<String>::default();
        for san in sans {
            r.push(san.to_string());
        }

        res.push(CsrExt::SanDns(r))
    }

    Ok(res)
}

pub fn run_csr_extensions(exts: &Vec<CsrExt>, extensions: &mut Stack<X509Extension>, req_builder: &X509ReqBuilder)
    -> Result<(), SslError> {
    for ext in exts {
        match ext {
            CsrExt::Client => {
                extensions.push(
                    X509Extension::new_nid(None, None, Nid::NETSCAPE_CERT_TYPE, "SSL Client")?
                )?;

                extensions.push(
                    X509Extension::new_nid(None, None, Nid::NETSCAPE_COMMENT, "Client Certificate")?
                )?;
            }
            CsrExt::Server => {
                extensions.push(
                    X509Extension::new_nid(None, None, Nid::NETSCAPE_CERT_TYPE, "SSL Server")?
                )?;

                extensions.push(
                    X509Extension::new_nid(None, None, Nid::NETSCAPE_COMMENT, "Server Certificate")?
                )?;
            }
            CsrExt::SanDns(dnss) => {
                let mut subject_alt_name = SubjectAlternativeName::new();

                for name in dnss {
                    subject_alt_name.dns(&name);
                }

                let subject_alt_name = subject_alt_name.build(&req_builder.x509v3_context(None))?;

                extensions.push(subject_alt_name)?;
            }
        }
    }
    Ok(())
}