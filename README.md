# PKCS padding oracle attacks: a CTF

## Introduction

This project contains a fork of the `mbedtls`  project, to which we added a program, `ssl_server3`, which is an SSL server with vulnerabilities allowing Bleichenbacher/Manger padding oracle attacks.

In this document we go over the various parts of the project and the CTF that it builds. All commands assume the working directory is the base of the project (where this README resides).

## CTF overview

The CTF consists of various stages (challenges), some of which are rely on previous stages. The participants are divided into groups, and each group gets a secret "mask" (a 16-bit number) from which it derives port numbers for each challenge, as we describe shortly. Each challenge consists of a few redacted scripts that implement Bleichenbacher or Manger attacks on a remote TLS server, an encrypted file to be decrypted using these attacks, and a port number. Each group derives from the port number a unique port number on which the server to be attacked by that group (for that challenge) is listening. The server for each stage is vulnerable in some way to these attacks, and the challenge is to implement the attacks, or relevant extensions thereof, in order to decrypt the given encryption, which contains the flag.

The stages are as follows:

1. The server for the first stage is a simplified PKCS 1 v1.5 padding oracle: once a connection is opened and TLS "hello" messages are exchanged, the server listens for client handshake messages containing an encrypted pre-master secret, attempts to decrypt and un-pad these messages, and sends a TLS error frame with a value that denotes success or failure in unpadding.
2. The server for the second stage is the same as the first stage, but it closes connections and stops responding to requests for fifteen minutes if a certain number of queries are exceeded in a single connection. As servers are multi-process, in this challenge the participants should implement multi-threaded attacks, querying several instances of the server simultaneously. In this stage (and in similar subsequent stages), the number of queries until the server "times out" and the number of queries required to decrypt the flag are matched in advance. Notice that all server processes (derived from the same instance) stop once one server has processed too many queries, in order to prevent groups from simply continuing the attack on a different instance. The time penalty is also "harsh" in order to prevent groups from simply waiting and continuing the attack once the server is back online.
3. The server for the third stage does not provide a "direct" oracle, but does simulate a timing oracle: on successful unpadding, it sleeps for 50 milliseconds. The participants should implement the querying logic that times requests and answers accordingly.
4. The fourth stage is like the third stage but with the same challenge as in stage 2: the server disconnects once too many requests are made, so attacks should be made multi-threaded.
5. The server for the fifth stage does not provide a simple timing oracle, but rather sleeps for 0 to 100 milliseconds on successful unpadding of a message. Once again, the CTF participants should modify their querying code accordingly.
6. The sixth stage is to the fifth as the fourth is to the third.
7. The server for the seventh stage provides a simplified PKCS 1 OAEP padding oracle as in stage 1. In this stage, the Manger attack should be implemented.
8. Once again, stage 8 is a parallelized version of stage 7.

## Preparing the CTF

### Preparing flags and keys (the "flag pool")

As each challenge should have its own flag and RSA keys, the first thing to be done is to generate a pool of flags and corresponding keys (and encrypted flags, etc.)

Generating such a pool allows for flexibility when choosing keys for various challenges, as the keys and flags can be chosen such that a certain number of oracle queries is required in order to execute an attack fully and decrypt the flag file.

To generate a flag pool, run (from the project's root directory)

```
cd flag_pool
python3.8 generate_flag_pool.py -n <pool_size> -d .
```

Running this will create a directory in `flag_pool/` for every key/flag pair generated with a matching number, and a file `flag_pool/queries.json` that stores for each of these pairs the number of oracle queries required to run a Bleichenbacher or a Manger attack on the encrypted flag. As the script runs the attacks locally to determine the number of queries, it may take a while (it runs ten key-generation processes concurrently to make things a bit quicker). There's no particular need to delve into the results of this script as long as it terminates successfully.

### Preparing files and servers

To prepare the files and scripts needed for the CTF, run (from the root directory of the project),

```
./scripts/build.sh <num_of_groups>
```

This script will generate the following directories and files:

```
ctf/
	group_masks - mask values for ports for the group servers
	stage_XX/ - the directory for stage XX of the CTF
		flag - a file containing the flag for this stage
		queries - the number of queries needed to decrypt enc.bin
		port - the port to be published (each groups XORs with its mask)
		stage_XX.zip - the file given to the groups in the CTF
		group/ - a directory with the files given to the group
			enc.bin - PKCS encryption of the flag
			pubkey.bin - public key of the server
		server/ - files for running the stage's target server
			cert.crt - certificate file
			priv.key.pem - private key
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

The stage files in the `ctf` directory are taken from the flag pool according to the requirements of each stage (padding type and query range). To modify the number of stages or what's created for each stage, modify the `stages.json` file (more on this in the section below on adding and configuring stages).

The `zip` files are the files the groups download from the CTF platform. These files contain the files in `group/` (`enc.bin` and `pubkey.bin`) and any files in the directory `material/stage_XX` (such as documentation or redacted attack scripts). These files are replace in the base configuration of the CTF platform and are put in `ctf_import.zip`, as explained in the relevant section below.

The way the servers are configured is thus:

At the start of the event, each group gets a "secret" mask; these values are generated by `build.sh` and stored in `ctf/group_masks`. On each level, a port number is released (the same number for all groups); this is the port in the `port` file in each stage directory. Each group takes this number, XORs it with its mask, and gets the port number of the server to attack for that stage of the CTF. The `nginx` container forwards connections from the main machine to the server containers themselves; its configuration (`nginx/conf/nginx.conf`) holds all the ports and addresses, internal and external. In some stages, more than one server instance is run for each group, and more than one thread is generated in each server instance. These numbers are specified in `stages.json` and can be modified there (more on this soon). This detail is not visible (directly, at least) to the teams, as all servers are "internal" and the `nginx` container forwards connections from the teams to the servers themselves.

The `build_*.sh` files in the `scripts` directory are used by the `build.sh` script. The `run_*.sh` files are used by the `run.sh` script.

`nginx/conf/nginx.conf` is the configuration file for `nginx` stating the forwarding rules to be used for the various stages. We build an `nginx` docker image with this configuration.

It remains to run all the servers that are attacked during the challenges. We do this by running an `nginx` server that listens on a different (random) port for each stage and forwards connections to instances of the `mbedtls` server running elsewhere.

So to get everything going, run (after running `build.sh`, of course)

```
./scripts/run.sh
```

This will run the `nginx` container and **all** the server instances from the `nginx` directory in this project; this is to be run on the host machine. To run different server instances on different hosts, run only `./scripts/run_nginx.sh`, and take the commands needed for each stage from `scripts/run_servers.sh`, running them where needed.

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
docker run -p 80:8000 ctfd/ctfd
```

This will run CTFd on port 80 of your machine. You can then configure CTF through the web interface. `build.sh` run above creates the file `CTFd/ctf_import.zip` from the directory `CTFd/db_base`, which is an export of the latest CTF configurations. The script also updates the port numbers, flags and files of each challenge before creating `ctf_import.zip`; note that the scripts expect the names of the challenges and files to be of a certain format, as follows:

* Challenges should be called "Challenge \<number\>". Each challenge should be in one of two categories, "Bleichenbacher" or "Manger". The challenges should correspond to challenges in the project configurations thus: first all Bleichenbacher challenges, followed by all Manger challenges, in the same order. The challenge number in the challenge name should be the number of the challenge (1-based) in that category.
* Challenges should provide one file each, called `stage_<num>.zip`. These files are replaced by the script with newly created `zip` files for each stage.

To import the image, create a temporary CTF and the go to Admin Panel -> Backup -> Import to import the `ctf_import.zip` file. To update the image, make the changes you want (or create a new CTF from scratch if needed), and in the same menu as above, export it. CTFd will generate a ZIP file with a `db` directory in it; extract this directory to `CTFd/db` in the project.

### Adding and configuring stages

To add a stage to the CTF, the following things are required:

* Modify the `mbedtls` however's needed for the stage. The server receives a `stage` argument that states the stage number and thus tells between stages; see the section on modifications to MbedTLS below for more details.
* Add the stage to the stage list in `stages.json`. Currently, stages are configured by the following parameters (in this order):
  * The number of server instances to run. Each instance is a container instance. Each instance can also run multiple processes, as specified in the next value:
  * The number of processes each server instance should spawn.
  * The type of PKCS padding to use for the flag's encryption file (a string set to `PKCS_1_5` or to `PKCS_OAEP`).
  * The minimal number of queries needed to decrypt the flag for this stage. An appropriate flag is selected from the flag pool according to this value.
  * The maximal number of queries needed to decrypt the flag for this stage. An appropriate flag is selected from the flag pool according to this value.
  * The IP address of the host running the stage's server containers (for `nginx` configuration). Notice that for running stage containers on the same host as the `nginx` container, the IP address given should be `172.17.0.1`, which is the default IP of the docker host.
* Add the stage to the CTF in the CTFd platform and update the `CTFd/db_base` directory accordingly, as explained above.
* To add files given to the participants other than the public key and encrypted flag, add files to the directory `material/stage_XX`, where `XX` is the stage number. The CTF-building scripts will make sure these files are added to the `zip` file attached to the challenge.

## Solution scripts and tests

### Running the attack scripts

The attack scripts expect a public key file, and can also take a valid encryption of a message using the server's key (to skip the blinding phase of the Bleichenbacher attack); in the CTF, this message is the encrypted flag. To run the Bleichenbacher attack, for example, run

```
python3.8 attack_scripts/bleichenbacher.py -n <num_of_servers> -p <server_port> -s <server_ip> -c <enc_file> -k <pubkey_file> -l 1024 -g <stage_number>
```

The attack scripts expects there to be `<num_of_servers>`  servers listening with the appropriate oracle on the IP and port given (there may be one server instance with several processes, of course). The encryption and public key files are the relevant files (`enc.bin` and `pubkey.bin`, respectively) in the group's files from the flag pool (selected by `build.sh`, as shown above). Run the script with `--help` for more details. The script outputs the padded message given in `enc.bin` and (if found) its "unpadded" message, which should be the flag.

### Tests

In the `tests` directory there is a test script, to be run from the project root directory thus:

```
pytest tests/
```

We recommend installing `pytest-xdist` and parallelizing the tests:

```
pytest --dist=load -n <num_of_processes> tests/
```

The test runs the solution attack script for each stage for all groups, according to the configuration it reads from the various files in the project. Run the tests after running `build.sh` and `run.sh`, where all containers are run locally (or run them non-locally and modify the script so it runs attack scripts with a different server address).

## Modifications to MbedTLS

### General changes

The changes we made to make the server vulnerable cause the server to send a TLS alert frame after **every** client handshake frame with a special alert number indicating whether the padding was valid or not (according to the oracle given). This deviates slightly from (vulnerable) TLS behavior, as in the regular case, an alert frame may be sent after invalid messages but not after valid ones. This is to save time during the attack, so that instead of sending a ChangeCipherSpec message or waiting a certain amount of time for a response, the attacker immediately gets a response.

Moreover, after **every** client handshake frame, the server waits for **another** client handshake message, saving time on socket reopening. If the client closes the connection, then the server waits for a new connection (and subsequently a ClientHello message before entering the handshake loop again). This means that every instance of the server serves one client at a time, but does so continuously.

We also added to the server program the option `num_servers` which, if specified, tells the server how many separate processes to create so that requests can be made in parallel to the same server. The current maximum is 25 processes.

### MbedTLS code details

Here we list the functions in the flow of client handshake frame handling and describe the changes made to them.

* `main` in `programs/ssl/ssl_server3.c`
  * This is the main function of the server application. In the handshake loop (found after the label `handshake`), `MBEDTLS_ERR_SSL_DECODE_ERROR` indicates that the server should go back to waiting for a client handshake message. This is done by setting the error value to `MBEDTLS_ERR_SSL_CLIENT_RECONNECT`, exploiting an SSL feature (client reconnection) implemented in the original server code. Other errors (such as EOF's caused by the attacker closing their socket) cause the server to go back to listening for a new connection.
  * Command-line options are parsed in this function. The option `stage` was added and sets a global variable in `library/pk.c`, where we set the padding scheme on the RSA context struct if needed. This is not very elegant, but it's done as setting the scheme is simpler from the functions in `library/pk.c`. According to the value of this option, the server's behavior (stage-wise) is determined. In `library/common.h` there is an `enum` with the various stages.
  * We added `fork` calls before `mbedtls_accept` in order to create several instances of a server if needed.
  * In relevant stages, once a certain number of queries is handled by a single instance, all instances (forked from the same server) are stopped for a certain period of time, as explained above in the various stages.
* `mbedtls_ssl_handshake` and `mbedtls_ssl_handshake_step` in `library/ssl_tls.c`.
* `mbedtls_ssl_handshake_server_step` and `ssl_parse_client_key_exchange` in `library/ssl_tls12_server.c`.
* `ssl_parse_encrypted_pms` in `library/ssl_tls12_server.c`
  * Here we added the sending of alert messages according to unpadding results (for relevant stages). We also set the return value of the function to `MBEDTLS_ERR_SSL_DECODE_ERROR`, which is handled in `main` as described above. The error value in the alert message is determined by the error value returned; we added an error value, `MBEDTLS_ERR_RSA_PADDING_ORACLE`, to unpadding functions; this return value indicates the oracle should return that the padding is invalid.
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
  * We return `MBEDTLS_ERR_RSA_PADDING_ORACLE`, an error we added (as opposed to `MBEDTLS_ERR_RSA_INVALID_PADDING `which is the standard error) in case a padding error occurs. This is done (mainly) by invoking the `NOT_CONSTANT_TIME` macro in the function; this macro returns the new error value in the middle of the function in case of an error, or `usleep`s, or does other things according to the stage number.

For PKCS 1 OAEP (Manger),

* `mbedtls_rsa_rsaes_oaep_decrypt` in `library/rsa.c`
  * Decrypts with `mbedtls_rsa_private`.
  * Checks padding in "constant time"; here as well we install `NOT_CONSTANT_TIME` where needed to return the new error value.

