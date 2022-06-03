all: attack_scripts/ssl_client.cpython-38-x86_64-linux-gnu.so ssl_server2

mbedtls/programs/ssl/ssl_server2 mbedtls/programs/ssl/ssl_client.cpython-38-x86_64-linux-gnu.so:
	$(MAKE) -C mbedtls programs

ssl_server2: mbedtls/programs/ssl/ssl_server2
	cp $< $@

attack_scripts/ssl_client.cpython-38-x86_64-linux-gnu.so: mbedtls/programs/ssl/ssl_client.cpython-38-x86_64-linux-gnu.so
	cp $< $@

clean:
	$(MAKE) -C mbedtls clean
	rm -f attack_scripts/ssl_client.cpython-38-x86_64-linux-gnu.so ssl_server2

.PHONY: clean