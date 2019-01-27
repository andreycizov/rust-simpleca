# simpleca 

Generate custom CA certificates and sign them.


## Usage
```
>> simpleca --help
Simplistic self-signed CA generator 0.1
Andrey Cizov <acizov@gmail.com>

USAGE:
    simplecae [SUBCOMMAND]

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

SUBCOMMANDS:
    ca      generates a ca certificate from a given private key in PEM format
    csr     generates a certificate signing request
    help    Prints this message or the help of the given subcommand(s)
    key     generates a private key in PEM format
    sign    generates a ca certificate from a given private key in PEM format
```

```
>> simpleca ca --help
simpleca-ca 
generates a ca certificate from a given private key in PEM format

USAGE:
    simpleca ca [OPTIONS] <pkey> <output> --after <after> --before <before> --common-name <common name>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --after <after>                   [default: 3650]
        --before <before>                 [default: 0]
    -N, --common-name <common name>      
    -C, --country <country>              
    -O, --organisation <organisation>    
    -S, --state <state>                  

ARGS:
    <pkey>      
    <output>
```

```
>> simpleca csr --help 
simpleca-csr 
generates a certificate signing request

USAGE:
   simpleca csr [FLAGS] [OPTIONS] <cert> <pkey> <output> --common-name <common name>

FLAGS:
       --ext-client    
       --ext-server    
   -h, --help          Prints help information
   -V, --version       Prints version information

OPTIONS:
   -N, --common-name <common name>                          
   -C, --country <country>                                  
   -O, --organisation <organisation>                        
       --san-dns <Specify SubjectAltName DNS records>...    
   -S, --state <state>                                      

ARGS:
   <cert>      
   <pkey>      
   <output>
```

```
>> simpleca key gen --help 
simpleca-key-gen 
generate a private key or a public key

USAGE:
    simpleca key gen <output>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

ARGS:
    <output> 
```

```
>> simpleca key pub --help 
simpleca-key-pub 
generates a public key from private key in PEM format

USAGE:
   simpleca key pub <pkey> <output>

FLAGS:
   -h, --help       Prints help information
   -V, --version    Prints version information

ARGS:
   <pkey>      
   <output> 
```

```
>> simpleca sign --help 
simpleca-sign 
generates a ca certificate from a given private key in PEM format

USAGE:
    simpleca sign <cert> <pkey> <pubkey> <csr> <output> --after <after> --before <before>

FLAGS:
    -h, --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
        --after <after>       [default: 3650]
        --before <before>     [default: 0]

ARGS:
    <cert>      
    <pkey>      
    <pubkey>    
    <csr>       
    <output>
```



## License

`simpleca` is licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or
   http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or
   http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in Serde by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
