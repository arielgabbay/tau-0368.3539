all:
	$(MAKE) -C mbedtls programs

clean:
	$(MAKE) -C mbedtls clean

.PHONY: clean