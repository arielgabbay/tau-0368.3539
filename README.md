# Bleichenbacher/Manger attack implementations

## Introduction

This project contains a fork of the `mbedtls`  project, to which we added a program, `ssl_server3`, which is an SSL server with vulnerabilities allowing Bleichenbacher/Manger padding oracle attacks.

In this document we go over the various parts of the project. All commands assume the working directory is the base of the project (where this README resides).

## Preparing the CTF

### Preparing files and servers

To prepare the files and scripts needed for the CTF, run

```
./scripts/build.sh <num_of_groups> <servers_ip>
```

Where the number of groups is the number of groups participating in the CTF and the server IP is the IP address of the server on which the servers will run. This script will generate the following directories and files:

```
ctf/
	stage_XX/ - the directory for stage XX of the CTF
		flag - a file containing the flag for this stage
		group/ - a directory with the files given to the group
			enc.bin - PKCS encryption of the flag
			pubkey.bin - public key of the server
		server/ - files for running the stage's target server
			cert.crt - certificate file
			priv.key.pem - private key
			request.csr - byproduct
scripts/
	build_servers.sh
	run_servers.sh
	run_nginx.sh
nginx/
	conf/
		nginx.conf
CTFd/
	ctf_import.zip
```

To modify the number of stages or what's created for each stage, modify the `prepare.py` script (more on this soon).

The `build_*.sh` files in the `scripts` directory are used by the `build.sh` script. The `run_*.sh` files are used by the `run.sh` script.

`nginx/conf/nginx.conf` is the configuration file for `nginx` stating the forwarding rules to be used for the various stages. We build an `nginx` docker image with this configuration.

It remains to run all the servers that are attacked during the challenges. We do this by running an `nginx` server that listens on a different (random) port for each stage and forwards connections to instances of the `mbedtls` server running elsewhere.

So to get everything going, run (after running `build.sh`, of course)

```
./scripts/run.sh
```

This will run the `nginx` container and **all** the server instances from the `nginx` directory in this project; this is to be run on the host machine. Support for several hosts for the servers can be added to the `prepare.py` script.

Furthermore, as each server instance can hold several connections simultaneously (if required), the `prepare.py` script specifies how many server instances to run per group and how many listening processes to require of each server; to change this, modify the script.

To build the server binary manually for testing, run

```
make -C mbedtls/ programs
```

and then run the server using a command as in `servers/Dockerfile`,

```
mbedtls/programs/ssl/ssl_server3 key_file=<...>/priv.key.pem crt_file=<...>/cert.crt force_version=tls12 force_ciphersuite=TLS-RSA-PSK-WITH-AES-128-CBC-SHA256 psk=abcdef stage=<stage> num_servers=<num_threads> server_port=<port>
```

### Preparing the platform

We recommend using `CTFd` to run the CTF. To do so, after preparing all files for the CTF, run

```
docker run -p 80:8000 -it ctfd/ctfd
```

This will run CTFd on port 80 of your machine. You can then configure CTF through the web interface. `build.sh` run above creates the file `CTFd/ctf_import.zip` from the directory `CTFd/db`, which is an export of the latest CTF configurations. To import this image, create a temporary CTF and the go to Admin Panel -> Backup -> Import to import the `ctf_import.zip` file. To update the image, make the changes you want (or create a new CTF from scratch if needed), and in the same menu as above, export it. CTFd will generate a ZIP file with a `db` directory in it; extract this directory to `CTFd/db` in the project.

### Adding stages

To add a stage to the CTF, the following things are required:

* Modify the `mbedtls` however's needed for the stage. The server receives a `stage` argument that states the stage number and thus tells between stages; see the section on modifications to MbedTLS below for more details.
* Add to the appropriate location in the `STAGES` list in `prepare.py` an instance of the `Stage` object with the parameters for the stage. Currently, stages are defined by two parameters: the number of server instances to run for each available server needed by the stage (for example, if we want every user to be able to attack five servers simultaneously, set this value to 5), and the type of PKCS padding to use for the flag's encryption file (set to `PKCS_1_5` or to `PKCS_OAEP`).
* Add the stage to the CTF in the CTFd platform and update the `CTFd/db` directory accordingly, as explained above.

## Running the attack

The attack scripts expect a public key file, and can also take a valid encryption of a message using the server's key (to skip the blinding phase of the Bleichenbacher attack); in the CTF, this message is the encrypted flag. To run the Bleichenbacher attack, for example, run

```
python3.8 attack_scripts/bleichenbacher.py -n <num_of_servers> -p <first_port_number> -s <server_ip> -c <enc_file> -k <pubkey_file> -l 1024
```

The attack scripts expects there to be `<num_of_servers>`  servers on consecutive ports starting from `<first_port_number>` listening with the appropriate oracle. The encryption and public key files are the relevant files (`enc.bin` and `pubkey.bin`, respectively) in the group's files generated by `prepare.py` and shown above. Run the script with `--help` for more details. The script outputs the padded message given in `enc.bin` and (if found) its "unpadded" message, which should be the flag.

Notice that valid encryptions can also be generated at will by the attacker given the server's public key.

## Modifications to MbedTLS

### General changes

The changes we made to make the server vulnerable cause the server to send a TLS alert frame after **every** client handshake frame with a special alert number indicating whether the padding was valid or not (according to the oracle given). This deviates slightly from (vulnerable) TLS behavior, as in the regular case, an alert frame may be sent after invalid messages but not after valid ones. This is to save time during the attack, so that instead of sending a ChangeCipherSpec message or waiting a certain amount of time for a response, the attacker immediately gets a response.

Moreover, after **every** client handshake frame, the server waits for **another** client handshake message, saving time on socket reopening. If the client closes the connection, then the server waits for a new connection (and subsequently a ClientHello message before entering the handshake loop again). This means that every instance of the server serves one client at a time, but does so continuously.

We also added to the server program the option `num_servers` which, if specified, tells the server how many separate processes to create so that requests can be made in parallel to the same server. The current maximum is 25 processes.

### MbedTLS code details

Here we list the functions in the flow of client handshake frame handling and describe the changes made to them.

* `main` in `programs/ssl/ssl_server3.c`
  * This is the main function of the server application. In the handshake loop (found after the label `handshake`), `MBEDTLS_ERR_SSL_DECODE_ERROR` indicates that the server should go back to waiting for a client handshake message. This is done by setting the error value to `MBEDTLS_ERR_SSL_CLIENT_RECONNECT`, exploiting an SSL feature (client reconnection) implemented in the original server code. Other errors (such as EOF's caused by the attacker closing their socket) cause the server to go back to listening for a new connection.
  * Command-line options are parsed in this function. The option `stage` was added and sets a global variable in `library/pk.c`, where we set the padding scheme on the RSA context struct if needed. This is not very elegant, but it's done as setting the scheme is simpler from the functions in `library/pk.c`.
  * We added `fork` calls before `mbedtls_accept` in order to create several instances of a server if needed.
* `mbedtls_ssl_handshake` and `mbedtls_ssl_handshake_step` in `library/ssl_tls.c`.
* `mbedtls_ssl_handshake_server_step` and `ssl_parse_client_key_exchange` in `library/ssl_tls12_server.c`.
* `ssl_parse_encrypted_pms` in `library/ssl_tls12_server.c`
  * Here we added the sending of alert messages according to unpadding results. We also set the return value of the function to `MBEDTLS_ERR_SSL_DECODE_ERROR`, which is handled in `main` as described above. The error value in the alert message is determined by the error value returned; we added an error value, `MBEDTLS_ERR_RSA_PADDING_ORACLE`, to unpadding functions; this return value indicates the oracle should return that the padding is invalid.
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