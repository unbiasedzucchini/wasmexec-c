FROM alpine:3.20 AS builder

RUN apk add --no-cache gcc musl-dev make pkgconf curl \
    sqlite-dev sqlite-static

# Build libmicrohttpd from source without HTTPS to avoid gnutls deps
RUN curl -fsSL https://ftp.gnu.org/gnu/libmicrohttpd/libmicrohttpd-0.9.77.tar.gz | tar xz && \
    cd libmicrohttpd-0.9.77 && \
    ./configure --prefix=/usr/local --enable-static --disable-shared --disable-https --disable-doc --disable-examples && \
    make -j$(nproc) && make install

WORKDIR /src
COPY . .

# Build with static linking — no gnutls needed
RUN make clean && make CC=gcc \
    CFLAGS="-O2 -Wall -Wextra -Wno-unused-parameter -std=c11 -I/usr/local/include" \
    LDFLAGS="-static -L/usr/local/lib -lmicrohttpd -lsqlite3 -lpthread -lm" \
    server

# Verify it's static
RUN file server && ldd server 2>&1 || true

FROM scratch
COPY --from=builder /src/server /server
EXPOSE 8000
ENTRYPOINT ["/server"]
