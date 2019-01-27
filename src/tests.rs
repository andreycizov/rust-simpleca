// create tests where SslConnector is created, CA is created and checked against that CA

use openssl::ssl::SslAcceptor;
use openssl::ssl::SslMethod;

use crate::*;
use std::net::{TcpListener, TcpStream};
use std::thread;
use openssl::ssl::SslConnector;
use tempfile::tempdir;
use std::path::Path;
use std::fs::OpenOptions;
use std::io::Write;
use clap::App;
use crate::args::parser_name_builder;
use crate::args::parser_not_after_before;
use crate::args::matches_name_builder;
use crate::args::matches_not_after_before;
use crate::args::ParseError;
use crate::args::parser_csr_extensions;
use crate::args::matches_csr_extensions;
use crate::args::run_csr_extensions;
use crate::args::CsrExt;

fn priv_to_pub(server_key: &PKey<Private>) -> PKey<Public> {
    return PKey::<Public>::public_key_from_pem(server_key.public_key_to_pem().unwrap().as_ref()).unwrap();
}


fn create_name_validity(name: &str) -> Result<(X509Name, (Option<Asn1Time>, Option<Asn1Time>)), ParseError> {
    let app = App::new("asd");
    let app = parser_name_builder(app);
    let app = parser_not_after_before(app);
    let matches = app.get_matches_from(vec![
        "", "-N", name
    ]);

    Ok((matches_name_builder(&matches)?, matches_not_after_before(&matches)?))
}

fn create_server(name: &str) -> Result<(Vec<CsrExt>, X509Name, (Option<Asn1Time>, Option<Asn1Time>)), ParseError> {
    let app = App::new("asd");
    let app = parser_name_builder(app);
    let app = parser_csr_extensions(app);
    let app = parser_not_after_before(app);
    let matches = app.get_matches_from(vec![
        "", "-N", name, "--ext-server", "--san-dns", "localhost",
    ]);

    Ok((matches_csr_extensions(&matches)?, matches_name_builder(&matches)?, matches_not_after_before(&matches)?))
}

fn create_client(name: &str) -> Result<(Vec<CsrExt>, X509Name, (Option<Asn1Time>, Option<Asn1Time>)), ParseError> {
    let app = App::new("asd");
    let app = parser_name_builder(app);
    let app = parser_csr_extensions(app);
    let app = parser_not_after_before(app);
    let matches = app.get_matches_from(vec![
        "", "-N", name, "--ext-client"
    ]);

    Ok((matches_csr_extensions(&matches)?, matches_name_builder(&matches)?, matches_not_after_before(&matches)?))
}


#[test]
fn test_initialization() {
    let dir = tempdir().unwrap();

    let (name, val) = create_name_validity("ca").unwrap();

    let key = build_privkey().unwrap();
    let ca = build_ca_cert(
        &key,
        &name,
        &val,
    ).unwrap();

    let (exts, name, _) = create_server("localhost").unwrap();

    let server_key = build_privkey().unwrap();
    let server_csr = build_ca_req(
        &server_key,
        &name,
        |cert_builder| {
            let mut extensions = Stack::<X509Extension>::new()?;
            run_csr_extensions(&exts, &mut extensions, &cert_builder)?;

            Ok(())
        }
    ).unwrap();

    let (exts, name, val) = create_client("localhost").unwrap();

    let client_key = build_privkey().unwrap();
    let client_csr = build_ca_req(
        &client_key,
        &name,
        |cert_builder| {
            let mut extensions = Stack::<X509Extension>::new()?;
            run_csr_extensions(&exts, &mut extensions, &cert_builder)?;

            Ok(())
        }
    ).unwrap();

    let server_key_pub = priv_to_pub(&server_key);
    let client_key_pub = priv_to_pub(&client_key);

    let server_cert = build_ca_signed_cert(
        &ca,
        &key,
        &server_key_pub,
        &server_csr,
        &val,
        |_| {Ok(())}
    ).unwrap();

    let client_cert = build_ca_signed_cert(
        &ca,
        &key,
        &client_key_pub,
        &client_csr,
        &val,
        |_| {Ok(())}
    ).unwrap();

    let ca_file_name = dir.path().join(Path::new("ca"));

    let ca_file_name = dbg!(ca_file_name);

    OpenOptions::new().write(true).create_new(true).open(&ca_file_name).unwrap().write(&ca.to_pem().unwrap()).unwrap();

    let mut acceptor = SslAcceptor::mozilla_intermediate(SslMethod::tls()).unwrap();
    acceptor.set_certificate(&server_cert).unwrap();
    acceptor.set_private_key(&server_key).unwrap();
    acceptor.set_ca_file(&ca_file_name).unwrap();
    acceptor.check_private_key().unwrap();

    let acceptor = acceptor.build();

    let listener = TcpListener::bind("0.0.0.0:8443").unwrap();

    let mut connector = SslConnector::builder(SslMethod::tls()).unwrap();
    connector.set_certificate(&client_cert.clone()).unwrap();
    connector.set_private_key(&client_key).unwrap();
    connector.set_ca_file(&ca_file_name).unwrap();
    connector.check_private_key().unwrap();

    let connector = connector.build();


    thread::spawn(move || {
        let stream = TcpStream::connect("localhost:8443").unwrap();
        stream.set_nodelay(true).unwrap();
        //stream.set_nonblocking(true).unwrap();
        let mut stream = connector.connect("localhost", stream).unwrap();

        let buff = vec![1, 2, 3];
        stream.write(buff.as_ref()).unwrap();
    });

    for stream in listener.incoming() {
        let stream = stream.unwrap();
        stream.set_nodelay(true).unwrap();
        //stream.set_nonblocking(true).unwrap();
        let mut stream = acceptor.accept(stream).unwrap();

        let mut buff = Vec::<u8>::with_capacity(128);
        let a = stream.read_to_end(&mut buff).unwrap();
        assert_eq!(a, 3);
        break;
    }
}