# Some stuff

## Commands to run

Create an RSA key for the server and a certificate using openssl (or something else). We henceforth assume these files are called `priv.key.pem`  and `cert.crt`, respectively:

```
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out priv.key.pem
openssl req -new -key priv.key.pem -out request.csr
openssl x509 -req -days 365 -in request.csr -signkey priv.key.pem -out cert.crt
```



After running `make`, we can run the server:

```
./programs/ssl/ssl_server2 key_file=priv.key.pem crt_file=cert.crt force_version=tls12 force_ciphersuite=TLS-RSA-PSK-WITH-AES-128-CBC-SHA256 psk=abcdef
```

and then the client:

```
./programs/ssl/ssl_client2 force_version=tls12 auth_mode=optional force_ciphersuite=TLS-RSA-PSK-WITH-AES-128-CBC-SHA256 psk=abcdef
```

(Testing the server can be done with `openssl s_client -legacy_renegotiation -psk abcdef localhost:4433`).

To use your own encrypted PMS, add the argument `custom_pms=00112233`, with the value being the encoded hex string you want for the custom PMS.

To add vulnerabilities on bad padding, refer to `library/ssl_tls12_server.c`, line 3727.

Added code to `library/ssl_tls12_client.c` (e.g. line 2009) for custom encrypted PMS buffer. Refer to diffs for full details.