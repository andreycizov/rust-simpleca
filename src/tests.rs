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

fn priv_to_pub(server_key: &PKey<Private>) -> PKey<Public> {
    return PKey::<Public>::public_key_from_pem(server_key.public_key_to_pem().unwrap().as_ref()).unwrap();
}

#[test]
fn test_initialization() {
    let dir = tempdir().unwrap();


    let key = build_privkey().unwrap();
    let ca = build_ca_cert(&key).unwrap();

    let server_key = build_privkey().unwrap();
    let csr = build_ca_req(
        &server_key,
    ).unwrap();

    let client_key = build_privkey().unwrap();
    let client_csr = build_ca_req(
        &client_key,
    ).unwrap();

    let server_key_pub = priv_to_pub(&server_key);
    let client_key_pub = priv_to_pub(&client_key);

    let server_cert = build_ca_signed_cert_server(
        &ca,
        &key,
        &server_key_pub,
        &csr,
        vec!["localhost"],
    ).unwrap();

    let client_cert = build_ca_signed_cert_client(
        &ca,
        &key,
        &client_key_pub,
        &client_csr,
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
        let mut stream = connector.connect("localhost", stream).unwrap();

        let buff = vec![1, 2, 3];
        stream.write(buff.as_ref()).unwrap();
    });

    for stream in listener.incoming() {
        let stream = stream.unwrap();
        stream.set_nodelay(true).unwrap();
        let mut stream = acceptor.accept(stream).unwrap();

        let mut buff = Vec::<u8>::with_capacity(128);
        let a = stream.read_to_end(&mut buff).unwrap();
        assert_eq!(a, 3);
        break;
    }
}