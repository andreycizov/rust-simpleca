use openssl::asn1::Asn1Time;
use openssl::error::ErrorStack;
use openssl::pkey::{PKey, PKeyRef, Private, Public};
use openssl::rsa::Rsa;
use openssl::x509::*;
use openssl::x509::extension::*;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use clap::App;
use clap::SubCommand;
use clap::Arg;
use std::fs::OpenOptions;
use std::io::{Read, Write, Error as IOError};
use openssl::nid::Nid;
use openssl::stack::Stack;

fn build_privkey() -> Result<PKey<Private>, ErrorStack> {
    let rsa = Rsa::generate(2048)?;
    let privkey = PKey::from_rsa(rsa)?;

    Ok(privkey)
}

fn build_ca_cert(privkey: &PKey<Private>) -> Result<X509, ErrorStack> {
    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("C", "US")?;
    x509_name.append_entry_by_text("ST", "TX")?;
    x509_name.append_entry_by_text("O", "Some CA organization")?;
    x509_name.append_entry_by_text("CN", "ca test")?;
    let x509_name = x509_name.build();

    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;
    let serial_number = {
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };
    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(&x509_name)?;
    cert_builder.set_issuer_name(&x509_name)?;
    cert_builder.set_pubkey(&privkey)?;
    let not_before = Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    let not_after = Asn1Time::days_from_now(3650)?;
    cert_builder.set_not_after(&not_after)?;

    cert_builder.append_extension(BasicConstraints::new().critical().ca().build()?)?;
    cert_builder.append_extension(KeyUsage::new()
        .critical()
        .key_cert_sign()
        .crl_sign()
        .build()?)?;

    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(None, None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    cert_builder.sign(&privkey, MessageDigest::sha256())?;
    let cert = cert_builder.build();

    Ok(cert)
}

/// Make a X509 request with the given private key
fn build_ca_req(
    ca_cert: &X509Ref,
    privkey: &PKey<Private>,
    dns: Vec<&str>,
) -> Result<X509Req, ErrorStack> {
    let mut req_builder = X509ReqBuilder::new()?;
    req_builder.set_pubkey(&privkey)?;

    let mut x509_name = X509NameBuilder::new()?;
    x509_name.append_entry_by_text("C", "US")?;
    x509_name.append_entry_by_text("ST", "TX")?;
    x509_name.append_entry_by_text("O", "Some organization")?;
    x509_name.append_entry_by_text("CN", "www.example.com")?;
    let x509_name = x509_name.build();
    req_builder.set_subject_name(&x509_name)?;

    let mut extensions = Stack::<X509Extension>::new()?;

    extensions.push(BasicConstraints::new().build()?)?;

    extensions.push(KeyUsage::new()
        .critical()
        .non_repudiation()
        .digital_signature()
        .key_encipherment()
        .build()?)?;


    extensions.push(
        X509Extension::new_nid(None, None, Nid::NETSCAPE_CERT_TYPE, "SSL Server")?
    )?;

    extensions.push(
        X509Extension::new_nid(None, None, Nid::NETSCAPE_COMMENT, "Server Certificate")?
    )?;

    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&req_builder.x509v3_context(None))?;
    extensions.push(subject_key_identifier)?;

    let auth_key_identifier = AuthorityKeyIdentifier::new()
        .keyid(false)
        .issuer(false)
        .build(&req_builder.x509v3_context(None))?;
    extensions.push(auth_key_identifier)?;

    let mut subject_alt_name = SubjectAlternativeName::new();

    for name in dns {
        subject_alt_name.dns(name);
    }

    let subject_alt_name = subject_alt_name.build(&req_builder.x509v3_context(None))?;

    extensions.push(subject_alt_name)?;

    req_builder.add_extensions(&extensions);

    req_builder.sign(&privkey, MessageDigest::sha256())?;
    let req = req_builder.build();
    Ok(req)
}

fn build_ca_signed_cert_server(
    ca_cert: &X509Ref,
    ca_privkey: &PKeyRef<Private>,
    pubkey: &PKey<Public>,
    req: &X509Req,
) -> Result<X509, ErrorStack> {


    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;
    let serial_number = {
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };

    //let req = build_ca_req(&ca_cert, &privkey, dns)?;

    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(req.subject_name())?;
    cert_builder.set_issuer_name(ca_cert.subject_name())?;
    cert_builder.set_pubkey(pubkey)?;
    let not_before = Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    let not_after = Asn1Time::days_from_now(3650)?;
    cert_builder.set_not_after(&not_after)?;

    for x in req.extensions()? {
        cert_builder.append_extension(x);
    }

    //cert_builder.x509v3_context;

    cert_builder.sign(&ca_privkey, MessageDigest::sha256())?;
    let cert = cert_builder.build();

    Ok(cert)
}

#[derive(Debug)]
pub enum LoadError {
    IO(IOError),
    OpenSSL(ErrorStack),
}

impl From<IOError> for LoadError {
    fn from(x: IOError) -> Self { LoadError::IO(x) }
}

impl From<ErrorStack> for LoadError {
    fn from(x: ErrorStack) -> Self { LoadError::OpenSSL(x)}
}

fn pkey_from_file(file: &mut Read) -> Result<PKey<Private>, LoadError> {
    let mut pkey_bytes = Vec::<u8>::with_capacity(2048);
    file.read_to_end(&mut pkey_bytes)?;
    let res = PKey::<Private>::private_key_from_pem(pkey_bytes.as_ref())?;
    Ok(res)
}


fn cert_from_file(file: &mut Read) -> Result<X509, LoadError> {
    let mut pkey_bytes = Vec::<u8>::with_capacity(2048);
    file.read_to_end(&mut pkey_bytes)?;
    let res = X509::from_pem(pkey_bytes.as_ref())?;
    Ok(res)
}

fn main() {
    let matches = App::new("Simplistic self-signed CA generator")
        .version("0.1")
        .author("Andrey Cizov <acizov@gmail.com>")
        .subcommand(
            SubCommand::with_name("pkey")
                .about("generates a private key in PEM format")
                .arg(
                    Arg::with_name("output")
                        .required(true)
                        .index(1)
                )
        )
        .subcommand(
            SubCommand::with_name("ca")
                .about("generates a ca certificate from a given private key in PEM format")
                .arg(
                    Arg::with_name("pkey")
                        .required(true)
                        .index(1)
                )
                .arg(
                    Arg::with_name("output")
                        .required(true)
                        .index(2)
                )
        )
        .subcommand(
            SubCommand::with_name("server")
                .about("generates a ca certificate from a given private key in PEM format")
                .arg(
                    Arg::with_name("ca_cert")
                        .required(true)
                        .index(1)
                )
                .arg(
                    Arg::with_name("ca_pkey")
                        .required(true)
                        .index(2)
                )
                .arg(
                    Arg::with_name("pkey")
                        .required(true)
                        .index(3)
                )
                .arg(
                    Arg::with_name("output")
                        .required(true)
                        .index(4)
                )
                .arg(
                    Arg::with_name("alt_names")
                        .required(true)
                        .multiple(true)
                )
        )
        .get_matches();

    let open_read = OpenOptions::new().read(true).clone();
    let open_write = OpenOptions::new().write(true).create_new(true).clone();

    if let Some(matches) = matches.subcommand_matches("pkey") {
        let filename = matches.value_of("output").unwrap();
        let mut file = open_write.open(filename).unwrap();

        let pkey = build_privkey().unwrap();

        let serialized = pkey.private_key_to_pem_pkcs8().unwrap();

        file.write(serialized.as_ref()).unwrap();
    }

    if let Some(matches) = matches.subcommand_matches("ca") {
        let file_pkey = matches.value_of("pkey").unwrap();
        let file_out = matches.value_of("output").unwrap();

        let pkey = pkey_from_file(&mut open_read.open(file_pkey).unwrap()).unwrap();

        let cert = build_ca_cert(&pkey).unwrap();

        open_write.open(file_out).unwrap().write(cert.to_pem().unwrap().as_ref()).unwrap();
    }

    if let Some(matches) = matches.subcommand_matches("server") {
        let file_ca_cert = matches.value_of("ca_cert").unwrap();
        let file_ca_pkey = matches.value_of("ca_pkey").unwrap();
        let file_pkey = matches.value_of("pkey").unwrap();
        let file_out = matches.value_of("output").unwrap();
        let alt_names: Vec<&str> = matches.values_of("alt_names").unwrap().collect();

        let ca_cert = cert_from_file(&mut open_read.open(file_ca_cert).unwrap()).unwrap();
        let ca_pkey = pkey_from_file(&mut open_read.open(file_ca_pkey).unwrap()).unwrap();
        let pkey = pkey_from_file(&mut open_read.open(file_pkey).unwrap()).unwrap();

        let cert = build_ca_signed_cert_server(
            &ca_cert,
            &ca_pkey,
            &pkey,
            alt_names
        ).unwrap();

        open_write.open(file_out).unwrap().write(cert.to_pem().unwrap().as_ref()).unwrap();
    }
}