# Bleichenbacher/Manger attack implementations

## Introduction

This project contains a fork of the `mbedtls`  project, to which we added a program, `ssl_server3`, which is an SSL server with vulnerabilities allowing Bleichenbacher/Manger padding oracle attacks.

In this document we go over the various parts of the project.

## Running the attacks

First, create an RSA key for the server and a certificate using openssl (or something else). We henceforth assume these files are called `priv.key.pem`  and `cert.crt`, respectively:

```
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out priv.key.pem
openssl req -new -key priv.key.pem -out request.csr
openssl x509 -req -days 365 -in request.csr -signkey priv.key.pem -out cert.crt
```

Then build the `mbedtls`   server; in the `mbedtls`  directory, run

```
make -C programs ssl/ssl_server3
```

We can then run the server:

```
mbedtls/programs/ssl/ssl_server3 key_file=priv.key.pem crt_file=cert.crt force_version=tls12 force_ciphersuite=TLS-RSA-PSK-WITH-AES-128-CBC-SHA256 psk=abcdef
```

To use PKCS 1 v1.5 (for a Bleichenbacher oracle), this line is sufficient. To use PKCS 1 OAEP (for a Manger oracle), add the argument `oaep_padding=1`.

The default port on which the server listens is 4433. To change this (for example when running several servers simultaneously), add the argument `server_port=<port_number_here>`.

The attack scripts expect a public key file, and can also take a valid encryption of a message using the server's key (to skip the blinding phase of the Bleichenbacher attack). To generate such files, run the script `gen_params.py`  in the directory where the key file you generated beforehand. This will create two new files, `enc.bin`, a valid encryption, and `pubkey.bin`, the public key (`N`  and `e`). The attack scripts know how to extract the needed information from these files. To run the Bleichenbacher attack, for example, run

```
python3.8 attack_scripts/bleichenbacher.py -n <num_of_servers> -p <first_port_number> -s <server_ip> -c enc.bin -k pubkey.bin -l 1024
```

The attack scripts expects there to be `<num_of_servers>`  servers on consecutive ports starting from `<first_port_number>` listening with the appropriate oracle. Run the script with `--help` for more details.

Notice that valid encryptions can also be generated at will by the attacker given the server's public key.

## Modifications to MbedTLS

### General changes

The changes we made to make the server vulnerable cause the server to send a TLS alert frame after **every** client handshake frame with a special alert number indicating whether the padding was valid or not (according to the oracle given). This deviates slightly from (vulnerable) TLS behavior, as in the regular case, an alert frame may be sent after invalid messages but not after valid ones. This is to save time during the attack, so that instead of sending a ChangeCipherSpec message or waiting a certain amount of time for a response, the attacker immediately gets a response.

Moreover, after **every** client handshake frame, the server waits for **another** client handshake message, this saving on socket reopening. If the client closes the connection, then the server waits for a new connection (and subsequently a ClientHello message before entering the handshake loop again). This means that every instance of the server serves one client at a time, but does so continuously.

### MbedTLS code details

Here we list the functions in the flow of client handshake frame handling and describe the changes made to them.

* `main` in `programs/ssl/ssl_server.c`
  * This is the main function of the server application. In the handshake loop (found after the label `handshake`), `MBEDTLS_ERR_SSL_DECODE_ERROR` indicates that the server should go back to waiting for a client handshake message. This is done by setting the error value to `MBEDTLS_ERR_SSL_CLIENT_RECONNECT`, exploiting an SSL feature (client reconnection) implemented in the original server code. Other errors (such as EOF's caused by the attacker closing their socket) cause the server to go back to listening for a new connection.
  * Command-line options are parsed in this function. The option `oaep_padding` was added and sets a global variable in `library/pk.c`, where we set the padding scheme on the RSA context struct if needed. This is not very elegant, but it's done as setting the scheme is simpler from the functions in `library/pk.c`.
* `mbedtls_ssl_handshake` and `mbedtls_ssl_handshake_step` in `library/ssl_tls.c`.
* `mbedtls_ssl_handshake_server_step` and `ssl_parse_client_key_exchange` in `library/ssl_tls12_server.c`.
* `ssl_parse_encrypted_pms` in `library/ssl_tls12_server.c`
  * Here we added the sending of alert messages according to unpadding results. We also set the return value of the function to `MBEDTLS_ERR_SSL_DECODE_ERROR`, which is handled in `main` as described above. The error value in the alert message is determined by the error value returned; we added an error value, `MBEDTLS_ERR_RSA_PADDING_ORACLE`, to unpadding functions; this return value indicates the oracle should return that the padding in invalid.
* `ssl_decrypt_encrypted_pms` in `library/ssl_tls12_server.c`.
* `mbedtls_pk_decrypt` in `library/pk.c`
  * Here we set the padding scheme on the RSA context struct if needed.
  * This function calls `ctx->pk_info->decrypt_func`, which winds up in
* `mbedtls_rsa_pkcs1_decrypt` in `library/rsa.c`
  * This function chooses between PKCS versions according to the value set above.

For PKCS 1 v1.5 (Bleichenbacher),

* `mbedtls_rsa_rsaes_pkcs1_v15_decrypt` in `library.rsa.c`
  * Decrypts with `mbedtls_rsa_private` and removes padding with
* `mbedtls_ct_rsaes_pkcs1_v15_unpadding` in `library/constant_time.c`
  * We return `MBEDTLS_ERR_RSA_PADDING_ORACLE`, an error we added (as opposed to `MBEDTLS_ERR_RSA_INVALID_PADDING `which is the standard error) in case a padding error occurs. This is done (mainly) by invoking the `NOT_CONSTANT_TIME` macro in the function; this macro returns the new error value in the middle of the function in case of an error.

For PKCS 1 OAEP (Manger),

* `mbedtls_rsa_rsaes_oaep_decrypt` in `library/rsa.c`
  * Decrypts with `mbedtls_rsa_private`.
  * Checks padding in "constant time"; here as well we install `NOT_CONSTANT_TIME` where needed to return the new error value.