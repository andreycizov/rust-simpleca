use clap::App;
use clap::SubCommand;
use clap::Arg;
use simpleca::*;
use std::fs::OpenOptions;

fn main() {
    let matches = App::new("Simplistic self-signed CA generator")
        .version("0.1")
        .author("Andrey Cizov <acizov@gmail.com>")
        .subcommand(
            SubCommand::with_name("key")
                .about("generates a private key in PEM format")
                .arg(
                    Arg::with_name("output")
                        .required(true)
                        .index(1)
                )
                .subcommand(
                    SubCommand::with_name("gen")
                    .about("generates a private key in PEM format")
                    .arg(
                        Arg::with_name("output")
                            .required(true)
                            .index(1)
                    )
                )
                .subcommand(
                    SubCommand::with_name("pub")
                        .about("generates a public key from private key in PEM format")
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
                    Arg::with_name("public_key")
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
                    Arg::with_name("public_key")
                        .required(true)
                        .index(3)
                )
                .arg(
                    Arg::with_name("csr")
                        .required(true)
                        .index(4)
                )
                .arg(
                    Arg::with_name("output")
                        .required(true)
                        .index(5)
                )
        )
        .get_matches();

    let open_read = OpenOptions::new().read(true).clone();
    let open_write = OpenOptions::new().write(true).create_new(true).clone();

    if let Some(matches) = matches.subcommand_matches("pkey") {
        let filename = matches.value_of("output").unwrap();
        let mut file = open_write.open(filename).unwrap();

        let pkey = build_privkey().unwrap();

        pkey_to_file(&mut file, &pkey).unwrap();
    }

    if let Some(matches) = matches.subcommand_matches("ca") {
        let file_pkey = matches.value_of("pkey").unwrap();
        let file_out = matches.value_of("output").unwrap();

        let pkey = pkey_from_file(&mut open_read.open(file_pkey).unwrap()).unwrap();

        let cert = build_ca_cert(&pkey).unwrap();

        let mut file = open_write.open(file_out).unwrap();

        cert_to_file(&mut file, &cert).unwrap();
    }

    if let Some(matches) = matches.subcommand_matches("server") {
        let file_ca_cert = matches.value_of("ca_cert").unwrap();
        let file_ca_pkey = matches.value_of("ca_pkey").unwrap();
        let file_csr = matches.value_of("csr").unwrap();
        let file_pkey = matches.value_of("public_key").unwrap();
        let file_out = matches.value_of("output").unwrap();
        let alt_names: Vec<&str> = matches.values_of("alt_names").unwrap().collect();

        let ca_cert = cert_from_file(&mut open_read.open(file_ca_cert).unwrap()).unwrap();
        let ca_pkey = pkey_from_file(&mut open_read.open(file_ca_pkey).unwrap()).unwrap();
        let csr = csr_from_file(&mut open_read.open(file_csr).unwrap()).unwrap();
        let pkey = pkey_public_from_file(&mut open_read.open(file_pkey).unwrap()).unwrap();

        let cert = build_ca_signed_cert_server(
            &ca_cert,
            &ca_pkey,
            &pkey,
            &csr,
            alt_names
        ).unwrap();

        let mut file = open_write.open(file_out).unwrap();

        cert_to_file(&mut file, &cert).unwrap();
    }
}