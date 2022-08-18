# PKCS padding oracle attacks: a CTF

## Introduction

This project contains a fork of the `mbedtls`  project, to which we added a program, `ssl_server3`, which is an SSL server with vulnerabilities allowing Bleichenbacher/Manger padding oracle attacks.

In this document we go over the various parts of the project and the CTF that it builds. All commands assume the working directory is the base of the project (where this README resides).

## CTF overview

The CTF consists of various stages (challenges), some of which are rely on previous stages. Each challenge consists of a few redacted scripts that implement Bleichenbacher or Manger attacks on a remote TLS server, an encrypted file to be decrypted using these attacks, and a port number on which a server is listening (on an address known to the candidates and determined by the organizers). The server for each stage is vulnerable in some way to these attacks, and the challenge is to implement the attacks, or relevant extensions thereof, in order to decrypt the given encryption, which contains the flag.

The stages are as follows:

1. The first challenge is an introductory challenge with a simplified version of the attacks implemented in later stages. Refer to the challenge description in the CTF platform and to the material given with the stage (`material/stage_00`) for more details; the PDF file there describing the oracle and the attack can be found on Overleaf [here](https://www.overleaf.com/read/nqhbvcmydsyz) (contact us if you want editing permissions for it). Once this stage is done, the next stage is made visible.
2. The server for the first Bleichenbacher stage is a simplified PKCS 1 v1.5 padding oracle: once a connection is opened and TLS "hello" messages are exchanged, the server listens for client handshake messages containing an encrypted pre-master secret, attempts to decrypt and un-pad these messages, and sends a TLS error frame with a value that denotes success or failure in unpadding. The material given for this stage also includes a summary of Bleichenbacher's attack with a pseudo-code implementation, intended to make implementation of the attack easier. The summary can also be found on Overleaf (in the [same link](https://www.overleaf.com/read/nqhbvcmydsyz)).
3. The server for the second Bleichenbacher stage is the same as the first stage, but flags expire after a few minutes (once a flag expires, a different flag, and hence a different encryption, is used). The flag timeout is such that the original attack isn't fast enough to retrieve flags on time; as servers are multi-processed, in this challenge the participants should implement multi-threaded attacks, querying several instances of the server simultaneously. There are a few methods to do this, and the template script given to the participants in this stage sends consecutive queries such that the server's work is somewhat parallelized.
4. In this stage and then next, the flag is not encrypting with padding (but rather with "textbook" RSA), and so the "blinding" phase of the attack needs to be implemented, as well.
5. Like the second Bleichenbacher stage, this stage is like the previous one but required parallelization.
6. The server for the fifth Bleichenbacher stage does not provide a "direct" oracle, but does simulate a timing oracle: on successful unpadding, it sleeps for 50 milliseconds. The participants should implement the querying logic that times requests and answers accordingly.
7. The sixth Bleichenbacher stage is like the fifth stage but with the same challenge as in stage 2: the flag is changed every few minutes, so attacks should be made multi-threaded.
8. The server for the seventh Bleichenbacher stage does not provide a simple timing oracle, but rather sleeps for 0 to 100 milliseconds on successful unpadding of a message. Once again, the CTF participants should modify their querying code accordingly.
9. The eighth Bleichenbacher stage is to the seventh as the sixth is to the fifth.
10. The server for the first Manger stage provides a simplified PKCS 1 OAEP padding oracle as in stage 1. In this stage, the Manger attack should be implemented. Once again, a summary of the attack implementation is provided and can be found on Overleaf (in the [same link](https://www.overleaf.com/read/nqhbvcmydsyz)).
11. Once again, stage 8 is a parallelized version of stage 7.

## Preparing the CTF

### Prerequisites

You'll need Python (we use version 3.8 and recommend you do as well), `docker`, and if you want to run the project's tests, the `pytest` package (more on this in the relevant section below). CTF participants will need Python installed, as well. To use the project `virtualenv`, the participants and you will need the `virtualenv` package (more on this soon).

### Creating and using the project `virtualenv`

To save time installing Python libraries needed for building the CTF and running various related scripts, the project contains a `requirements.txt` file with which you can create a `virtualenv`. Other parts of the CTF are all run in docker containers whose images are built in the project (more on this soon), so system requirements are minimal. If `virtualenv` is not installed on your machine, run

```
pip install virtualenv
```

To create the environment, choose a name for it (we suggest something ending with `_env` as it's in the `.gitignore` file), and run

```
virtualenv <env_name>
source <env_name>/bin/activate
pip install -r requirements.txt
```

To activate the environment later, run the second line above (`source <env_name>/bin/activate`); to deactivate it, run `deactivate`.

The same instructions are given to the CTF participants so they can also run the scripts given to them in the CTF challenges on their machines.

### Preparing files and servers

To prepare the files and scripts needed for the CTF, run (from the root directory of the project),

```
./scripts/build.sh <num_of_groups>
```

This script will generate the following directories and files:

```
ctf/
	server/ - file for running the target server(s)
		cert.crt - certificate file
		priv.key.pem - private key
		pubkey.bin - public key of the server
	<category>/ - the directory for stages of various categories
		stage_XX/ - the directory for stage number XX of this category
			port - the port on which the server for this stage listens
			files.zip - the file given to the groups in the CTF
scripts/
	build_servers.sh
	run_servers.sh
	run_nginx.sh
nginx/
	conf/
		nginx.conf
CTFd_export/
	ctf_import.zip
```

The `zip` files are the files the groups download from the CTF platform. These files contain the server's public key (currently the same for all stages, but this can be changed in the future if needed) and any files in the directory `material/stage_XX` (such as documentation or redacted attack scripts). These files are replaced in the base configuration of the CTF platform and are put in `ctf_import.zip`, as explained in the relevant section below.

The `nginx` container forwards connections from the main machine to the server containers themselves; its configuration (`nginx/conf/nginx.conf`) holds all the ports and addresses of the servers, internal and external, which are generated by `build.sh`. In some stages, more than one server instance is run for each group, and more than one thread is generated in each server instance. These numbers are specified in `stages.json` and can be modified there (more on this soon). This detail is not visible (directly, at least) to the teams, as all servers are "internal" and the `nginx` container forwards connections from the teams to the servers themselves.

The `build_*.sh` files in the `scripts` directory are used by the `build.sh` script. The `run_*.sh` files are used by the `run.sh` script.

`nginx/conf/nginx.conf` is the configuration file for `nginx` stating the forwarding rules to be used for the various stages. We build an `nginx` docker image with this configuration.

It remains to run all the servers that are attacked during the challenges. We do this by running an `nginx` server that listens on a different (random) port for each stage and forwards connections to instances of the `mbedtls` server running elsewhere.

So to get everything going, run (after running `build.sh`, of course)

```
./scripts/run.sh
```

This will run the `nginx` container and **all** the server instances from the `nginx` directory in this project; this is to be run on the host machine. To run different server instances on different hosts, run only `./scripts/run_nginx.sh`, and take the commands needed for each stage from `scripts/run_servers.sh`, running them where needed. This also runs the `CTFd` image on which the CTF is hosted.

To build the server binary manually for testing, run

```
make -C mbedtls/ programs
```

and then run the server using a command as in `servers/Dockerfile`,

```
mbedtls/programs/ssl/ssl_server3 key_file=<...>/priv.key.pem crt_file=<...>/cert.crt force_version=tls12 force_ciphersuite=TLS-RSA-PSK-WITH-AES-128-CBC-SHA256 psk=abcdef stage=<stage> num_servers=<num_threads> server_port=<port>
```

### The `CTFd` platform

The CTF is hosted on `CTFd`, with a few plugins of ours, on which we expand later in this document. The `CTFd` image is run by `run.sh`, but can be run manually thus:

```
cd CTFd/
docker-compose up
```

This will run CTFd on port 80 of your machine. You can then configure CTF through the web interface. `build.sh` run above creates the file `CTFd_export/ctf_import.zip` from the directory `CTFd_export/db_base`, which is an export of the latest CTF configurations. The script also updates the port numbers, flags and files of each challenge before creating `ctf_import.zip`; note that the scripts expect the names of the challenges and files to be of a certain format, as follows:

* Challenge names should match their names in `stages.json`.
* For the build scripts to add material from the `material` directory to files given to the groups in the challenge, the challenge should have an attached file called `files.zip`. This file is replaced by the script with a newly created `zip` file for each stage.
* Notice that as the server's key changes between builds, the `pool_flags.json` file in the exported directory is ignored, as flags encryptions differ.

To import the image, create a temporary CTF and the go to Admin Panel -> Backup -> Import to import the `ctf_import.zip` file. To update the image, make the changes you want (or create a new CTF from scratch if needed), and in the same menu as above, export it. `CTFd` will generate a ZIP file with a `db` directory in it; extract this directory to `CTFd_export/db_base` in the project.

The stages of the CTF in `CTFd` are challenges of the type "cookie", which is added by our plugin. This is a special type of challenge which allows a few relevant configurations:

* The minimal number of queries needed to decrypt flags for this stage. An appropriate flag is selected according to this value.
* The maximal number of queries needed to decrypt flags for this stage. An appropriate flag is selected according to this value.
* The life span of a flag in this challenge; flags can be changed once every certain period of time if needed.
* The padding type (NOPADDING, PKCS 1.5 or PKCS OAEP) used to generate flags. NOPADDING means "raw" (textbook) RSA is used. If the challenge's category is Bleichenbacher or Manger, then query limits on flag decryption will apply according to the number of queries required for the relevant attack; otherwise these fields are ignored.

The plugin runs a process on the `CTFd` container that generates flags and their encryptions in the background. An additional database table stores these flags, which are then used by the plugin when it selects flags according to the parameters given. Balancing the values of the number of queries to decrypt a flag and the flags' life span allows for enforcement of efficient or parallelized attacks. When adding a challenge in the admin panel of `CTFd`, make sure you select "cookie"-type challenges (if that's what you need) and that you fill in the various relevant fields (some are visible only after saving the challenge initially). When making "cookie" challenges visible, `CTFd` will warn you that no flag is configured; this is fine as the plugin takes care of flags. Notice that as flags are generated in a process on the `CTFd` container, if you add a challenge shortly after the container first runs, flags may not be available for it and an error will be displayed when creating the challenge. This is OK, as when flags are available, the challenge will work.

Another feature added by our plugins is a countdown clock on challenge pages, showing participants the amount of time left for a flag's validity (if relevant), and an extra "download" button that downloads the latest encrypted flag for each challenge (also on its page). Notice also that when submitting a flag, there are a few possible outputs: if the flag is correct and valid (still active for the challenge), it is accepted; if it's correct but no longer active (expired), a message stating this is displayed; if it's incorrect, there's an appropriate message; and if it's not in the correct format (not a 32-character hex string), a different message stating this is displayed.

The admin credentials for the CTF as currently saved in the database export are `admin`/`ceEteEefFadmiN`.

### Adding and configuring stages

To add a stage to the CTF, the following things are required:

* Modify the `mbedtls` however's needed for the stage. The server receives a `stage` argument that states the stage number and thus tells between stages; see the section on modifications to MbedTLS below for more details.
* Add the stage to the stage list in `stages.json`. Currently, stages are configured by the following parameters (in this order):
  * The stage's name in the `CTFd` database.
  * The number of server instances to run. Each instance is a container instance. Each instance can also run multiple processes, as can be specified in the docker build arguments (see below).
  * The IP address of the host running the stage's server containers (for `nginx` configuration). Notice that for running stage containers on the same host as the `nginx` container, the IP address given should be `172.17.0.1`, which is the default IP of the docker host.
  * The path of the directory in `material/` in which extra material to be given to the candidates for the challenge is found. This directory is zipped into `files.zip` which is then downloadable from the challenge page in `CTFd`.
  * The path of the dockerfile in `servers/` that builds server images for the stage.
  * A list of build arguments to said dockerfile.
* Add the stage to the CTF in the `CTFd` platform and update the `CTFd/db_base` directory accordingly, as explained above.
* If needed, add files given to the candidates in the challenge to the material directory as specified in `stages.json`.

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

The test runs the solution attack script for each stage, according to the configuration it reads from the various files in the project. Run the tests after running `build.sh` and `run.sh`, where all containers are run locally (or run them non-locally and modify the script so it runs attack scripts with a different server address).

Note that `pytest` and `pytest-xdist` are not included in the `requirements.txt` file, so if you're using the project's `virtualenv`, you'll need to `pip install` them.

Due to changes in the CTF structure, the tests are currently out of date and do not work with newer CTFs.

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

## `CTFd` plugin details

We give a few technical details of the `CTFd` plugins we developed:

The only two changes to `CTFd` that is are in the scope of a plugin are to `CTFd/api/v1/challenges.py`, where we added more arguments to the rendering of the challenge viewing page in order to display a countdown when flags expire, and to `docker-compose.yml`, where we removed the `nginx` image generated by `CTFd` by default; thus the `CTFd` container is directly accessible on the machine on which it is run (for example by `run.sh` in this project).

There are two plugins that together supply the additional features needed for this CTF:

`cookie_challenges` is a challenge-type plugin which is based on the "dynamic challenges" pluging that comes with `CTFd` and supplies more configuration options, as explained above (number of queries, padding scheme, flag expiry). As with dynamic challenges, the plugin creates another database table which is linked to the regular challenge table to contain these configurations. In the `assets` directory of the plugin (`CTFd/plugins/cookie_challenges/assets/`) there are the HTML and JS files for the creation, updating and viewing pages of the challenges. The main changes to these is the addition of the various configurations and the addition of the countdown clock and encrypted-flag-download-button to the viewing page.

`cookie_keys` is a plugin that manages the flags and their association to "cookie" challenges. It contains scripts that locally implement the attacks (Bleichenbacher and Manger) in order to find the number of queries required for different encrypted flags. On startup, it spawns a process that continuously generates flags and their encryptions and writes them to the container filesystem with the number of queries they require (until a certain number of flags are pending in the filesystem). The plugin reads these flags from the filesystem to the database when needed (to a new table called `pool_flags`), and from the database it selects flags for challenges when needed (when they're created or when their flags should be changed). If there are enough flags in the database, the plugin does not pull more flags from the filesystem, and so the flag-generating process can rest once there are sufficiently many flags standing by. This plugin also provides the API to the `cookie_challenges` plugin for retrieving, updating and adding/removing flags for challenges.

As `CTFd` generates a separate docker container for its database (`mariadb`), debugging the database or checking its status can be done thus, for example:

```
docker container exec -it ctfd_db_1 /bin/bash
root:/# mysql -u ctfd -p ctfd
Enter password: ctfd
MariaDB [ctfd]> select * from pool_flags;
```

Notice that the `CTFd/.data` directory holds the CTF database, so if you want to create a completely new image, remove this directory (for example when modifying things).

## Newer possible stages

* Manger challenges that require statistical analysis of several queries to determine padding status.
* Add two Manger challenges before the current one in which the flag is not padded.