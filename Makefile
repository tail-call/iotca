LDFLAGS := -lmbedtls -lmbedx509 -lmbedcrypto
CFLAGS := -g -D_GNU_SOURCE
OBJECTS := http.o jsmn.o directory.o rsa.c base64url.o main.o

iotca: $(OBJECTS)
	gcc ${LDFLAGS} ${CFLAGS} -o $@ ${OBJECTS}
