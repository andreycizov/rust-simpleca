use clap::App;
use clap::SubCommand;
use clap::Arg;
use simpleca::*;
use std::fs::OpenOptions;
use simpleca::args::*;
use openssl::stack::Stack;
use openssl::x509::X509Extension;

fn main() {
    let matches = App::new("Simplistic self-signed CA generator")
        .version("0.1")
        .author("Andrey Cizov <acizov@gmail.com>")
        .subcommand(
            SubCommand::with_name("key")
                .about("generates a private key in PEM format")
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
            parser_not_after_before(
                parser_name_builder(
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
            )
        )
        .subcommand(
            parser_not_after_before(
                SubCommand::with_name("sign")
                    .about("generates a ca certificate from a given private key in PEM format")
                    .arg(
                        Arg::with_name("cert")
                            .required(true)
                            .index(1)
                    )
                    .arg(
                        Arg::with_name("pkey")
                            .required(true)
                            .index(2)
                    )
                    .arg(
                        Arg::with_name("pubkey")
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
        )

        .subcommand(
            parser_csr_extensions(
                parser_name_builder(
                    SubCommand::with_name("csr")
                        .about("generates a certificate signing request")
                        .arg(
                            Arg::with_name("cert")
                                .required(true)
                                .index(1)
                        )
                        .arg(
                            Arg::with_name("pkey")
                                .required(true)
                                .index(2)
                        )
                        .arg(
                            Arg::with_name("output")
                                .required(true)
                                .index(3)
                        )
                )
            )
        )
        .get_matches();

    let open_read = OpenOptions::new().read(true).clone();
    let open_write = OpenOptions::new().write(true).create_new(true).clone();

    if let Some(matches) = matches.subcommand_matches("key") {
        if let Some(matches) = matches.subcommand_matches("gen") {
            let file_out = matches.value_of("output").unwrap();

            let pkey = build_privkey().unwrap();

            let mut file = open_write.open(file_out).unwrap();
            pkey_to_file(&mut file, &pkey).unwrap();
        } else if let Some(matches) = matches.subcommand_matches("pub") {
            let file_pkey = matches.value_of("pkey").unwrap();
            let file_out = matches.value_of("output").unwrap();
            let pkey = pkey_from_file(&mut open_read.open(file_pkey).unwrap()).unwrap();


            let mut file = open_write.open(file_out).unwrap();

            pkey_public_to_file(&mut file, &pkey).unwrap();
        } else {
            unreachable!("")
        }
    } else if let Some(matches) = matches.subcommand_matches("ca") {
        let file_pkey = matches.value_of("pkey").unwrap();
        let file_out = matches.value_of("output").unwrap();

        let pkey = pkey_from_file(&mut open_read.open(file_pkey).unwrap()).unwrap();

        let name = matches_name_builder(&matches).unwrap();
        let not_a_b = matches_not_after_before(&matches).unwrap();

        let cert = build_ca_cert(
            &pkey,
            &name,
            &not_a_b,
        ).unwrap();

        let mut file = open_write.open(file_out).unwrap();

        cert_to_file(&mut file, &cert).unwrap();
    } else if let Some(matches) = matches.subcommand_matches("csr") {
        let file_pkey = matches.value_of("pkey").unwrap();
        let file_out = matches.value_of("output").unwrap();

        let pkey = pkey_from_file(&mut open_read.open(file_pkey).unwrap()).unwrap();

        let name = matches_name_builder(&matches).unwrap();

        let exts = matches_csr_extensions(&matches).unwrap();

        let csr = build_ca_req(
            &pkey,
            &name,
            |cert_builder| {
                let mut extensions = Stack::<X509Extension>::new()?;

                run_csr_extensions(&exts, &mut extensions, cert_builder)?;

                cert_builder.add_extensions(&extensions)?;

                Ok(())
            },
        ).unwrap();

        let mut file = open_write.open(file_out).unwrap();

        csr_to_file(&mut file, &csr).unwrap();
    } else if let Some(matches) = matches.subcommand_matches("sign") {
        let file_cert = matches.value_of("cert").unwrap();
        let file_pkey = matches.value_of("pkey").unwrap();
        let file_pubkey = matches.value_of("pubkey").unwrap();
        let file_csr = matches.value_of("csr").unwrap();
        let file_out = matches.value_of("output").unwrap();

        let cert = cert_from_file(&mut open_read.open(file_cert).unwrap()).unwrap();
        let pkey = pkey_from_file(&mut open_read.open(file_pkey).unwrap()).unwrap();
        let pubkey = pkey_public_from_file(&mut open_read.open(file_pubkey).unwrap()).unwrap();
        let csr = csr_from_file(&mut open_read.open(file_csr).unwrap()).unwrap();

        let not_a_b = matches_not_after_before(&matches).unwrap();

        let rcert = build_ca_signed_cert(
            &cert,
            &pkey,
            &pubkey,
            &csr,
            &not_a_b,
            |_| { Ok(()) },
        ).unwrap();

        let mut file = open_write.open(file_out).unwrap();

        cert_to_file(&mut file, &rcert).unwrap();
    } else {
        eprintln!("invalid command");
        ::std::process::exit(-1);
    }
}