# wasmexec-c

HTTP server for content-addressable blob storage with WebAssembly execution.
Built with C, libmicrohttpd, SQLite, and wasm3.

## Build

```
sudo apt install libmicrohttpd-dev libsqlite3-dev wabt
make
```

## Run

```
./server [db_path] [port]
./server blobs.db 8000    # defaults
```

## API

| Method | Path | Description |
|--------|------|-------------|
| `PUT` | `/blobs` | Upload a blob. Returns `{"hash":"<sha256>"}`. |
| `GET` | `/blobs/:hash` | Retrieve a blob by its SHA-256 hash. |
| `POST` | `/execute/:hash` | Execute a wasm blob. Request body = input, response body = output. |

Blobs are content-addressable and immutable.

## Wasm Contract

Modules must export:
- `memory` — the module's linear memory
- `run(input_ptr: i32, input_len: i32) -> i32` — entry point

The host writes input bytes into the module's memory at offset `0x10000`,
then calls `run(0x10000, input_len)`.

`run` returns a pointer to the output, formatted as:
```
[output_len: u32 LE][output_bytes...]
```

No WASI. No imported functions. Pure computation.

## Test

```
# compile test modules
wat2wasm test/echo.wat -o test/echo.wasm
wat2wasm test/reverse.wat -o test/reverse.wasm

# start server, run tests
./server &
bash test/test.sh
```

## Example

```bash
# upload a wasm module
curl -s -X PUT --data-binary @test/echo.wasm http://localhost:8000/blobs
# {"hash":"a96bfc71..."}

# execute it
curl -s -X POST -d 'hello' http://localhost:8000/execute/a96bfc71...
# hello
```
