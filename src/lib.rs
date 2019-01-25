#[cfg(test)]
mod tests;

use openssl::asn1::Asn1Time;
use openssl::error::ErrorStack;
use openssl::pkey::{PKey, PKeyRef, Private, Public};
use openssl::rsa::Rsa;
use openssl::x509::*;
use openssl::x509::extension::*;
use openssl::bn::{BigNum, MsbOption};
use openssl::hash::MessageDigest;
use std::io::{Read, Write, Error as IOError};
use openssl::nid::Nid;
use openssl::stack::Stack;

pub fn build_privkey() -> Result<PKey<Private>, ErrorStack> {
    let rsa = Rsa::generate(2048)?;
    let privkey = PKey::from_rsa(rsa)?;

    Ok(privkey)
}

pub fn build_ca_cert(privkey: &PKey<Private>) -> Result<X509, ErrorStack> {
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
pub fn build_ca_req(
    privkey: &PKey<Private>,
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

    //let mut extensions = Stack::<X509Extension>::new()?;



    //req_builder.add_extensions(&extensions)?;

    req_builder.sign(&privkey, MessageDigest::sha256())?;
    let req = req_builder.build();
    Ok(req)
}

pub fn build_ca_signed_cert_server(
    ca_cert: &X509Ref,
    ca_privkey: &PKeyRef<Private>,
    pubkey: &PKey<Public>,
    req: &X509Req,
    dns: Vec<&str>,
) -> Result<X509, ErrorStack> {
    build_ca_signed_cert(ca_cert, ca_privkey, pubkey, req, |cert_builder: &mut X509Builder| {
        cert_builder.append_extension(
            X509Extension::new_nid(None, None, Nid::NETSCAPE_CERT_TYPE, "SSL Server")?
        )?;

        cert_builder.append_extension(
            X509Extension::new_nid(None, None, Nid::NETSCAPE_COMMENT, "Server Certificate")?
        )?;

        let mut subject_alt_name = SubjectAlternativeName::new();

        for name in dns {
            subject_alt_name.dns(name);
        }

        let subject_alt_name = subject_alt_name.build(&cert_builder.x509v3_context(Some(ca_cert), None))?;

        cert_builder.append_extension(subject_alt_name)?;

        Ok(())
    })
}

pub fn build_ca_signed_cert_client(
    ca_cert: &X509Ref,
    ca_privkey: &PKeyRef<Private>,
    pubkey: &PKey<Public>,
    req: &X509Req,
) -> Result<X509, ErrorStack> {
    build_ca_signed_cert(ca_cert, ca_privkey, pubkey, req, |cert_builder: &mut X509Builder| {
        cert_builder.append_extension(
            X509Extension::new_nid(None, None, Nid::NETSCAPE_CERT_TYPE, "SSL Client")?
        )?;

        cert_builder.append_extension(
            X509Extension::new_nid(None, None, Nid::NETSCAPE_COMMENT, "Client Certificate")?
        )?;

        Ok(())
    })
}

pub fn build_ca_signed_cert<F>(
    ca_cert: &X509Ref,
    ca_privkey: &PKeyRef<Private>,
    pubkey: &PKey<Public>,
    req: &X509Req,
    map: F
) -> Result<X509, ErrorStack>
where F: FnOnce(&mut X509Builder) -> Result<(), ErrorStack> {
    let mut cert_builder = X509::builder()?;
    cert_builder.set_version(2)?;
    let serial_number = {
        let mut serial = BigNum::new()?;
        serial.rand(159, MsbOption::MAYBE_ZERO, false)?;
        serial.to_asn1_integer()?
    };

    cert_builder.set_serial_number(&serial_number)?;
    cert_builder.set_subject_name(req.subject_name())?;
    cert_builder.set_issuer_name(ca_cert.subject_name())?;
    cert_builder.set_pubkey(pubkey)?;

    let not_before = Asn1Time::days_from_now(0)?;
    cert_builder.set_not_before(&not_before)?;
    let not_after = Asn1Time::days_from_now(3650)?;
    cert_builder.set_not_after(&not_after)?;

    cert_builder.append_extension(BasicConstraints::new().build()?)?;

    cert_builder.append_extension(KeyUsage::new()
        .critical()
        .non_repudiation()
        .digital_signature()
        .key_encipherment()
        .build()?)?;

    let subject_key_identifier =
        SubjectKeyIdentifier::new().build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
    cert_builder.append_extension(subject_key_identifier)?;

    let auth_key_identifier = AuthorityKeyIdentifier::new()
        .keyid(false)
        .issuer(false)
        .build(&cert_builder.x509v3_context(Some(ca_cert), None))?;
    cert_builder.append_extension(auth_key_identifier)?;

    map(&mut cert_builder)?;

    let d = req.extensions().or_else(|_| Stack::<_>::new())?;
    for ext in d {
        cert_builder.append_extension(ext)?;
    }

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
    fn from(x: ErrorStack) -> Self { LoadError::OpenSSL(x) }
}

pub fn pkey_from_file(file: &mut Read) -> Result<PKey<Private>, LoadError> {
    let mut pkey_bytes = Vec::<u8>::with_capacity(2048);
    file.read_to_end(&mut pkey_bytes)?;
    let res = PKey::<Private>::private_key_from_pem(pkey_bytes.as_ref())?;
    Ok(res)
}

pub fn pkey_public_from_file(file: &mut Read) -> Result<PKey<Public>, LoadError> {
    let mut pkey_bytes = Vec::<u8>::with_capacity(2048);
    file.read_to_end(&mut pkey_bytes)?;

    let res = PKey::<Public>::public_key_from_pem(pkey_bytes.as_ref())?;
    Ok(res)
}

pub fn pkey_to_file(file: &mut Write, pkey: &PKey<Private>) -> Result<(), LoadError> {
    file.write(pkey.private_key_to_pem_pkcs8()?.as_ref())?;

    Ok(())
}

pub fn pkey_public_to_file(file: &mut Write, pkey: &PKey<Public>) -> Result<(), LoadError> {
    file.write(pkey.public_key_to_pem()?.as_ref())?;

    Ok(())
}

pub fn cert_from_file(file: &mut Read) -> Result<X509, LoadError> {
    let mut pkey_bytes = Vec::<u8>::with_capacity(2048);
    file.read_to_end(&mut pkey_bytes)?;
    let res = X509::from_pem(pkey_bytes.as_ref())?;
    Ok(res)
}


pub fn cert_to_file(file: &mut Write, cert: &X509) -> Result<(), LoadError> {
    file.write(cert.to_pem()?.as_ref())?;

    Ok(())
}

pub fn csr_from_file(file: &mut Read) -> Result<X509Req, LoadError> {
    let mut pkey_bytes = Vec::<u8>::with_capacity(2048);
    file.read_to_end(&mut pkey_bytes)?;
    let res = X509Req::from_pem(pkey_bytes.as_ref())?;
    Ok(res)
}

pub fn csr_to_file(file: &mut Write, csr: &X509Req) -> Result<(), LoadError> {
    file.write(csr.to_pem()?.as_ref())?;

    Ok(())
}

