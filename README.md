## Toxisyscall

Improper error handling, such as when executing system calls, is a common source of bugs. Toxisyscall help inject errors for the requested syscalls to help test the exceptional code paths.

This project is very young, expect the codebase to evolve quickly. For an example on how to use it, check out the integration tests under `test/`. A "client" for Rust is provided in this crate under `src/client.src`.

The name was inspired by [Toxiproxy](https://github.com/Shopify/toxiproxy).

## Test

Install `just` (`cargo install just`) and run `just test`.

## TODO

- Add/improve multiprocess support
- Allow dry run mode
- Remove exited processes
- Decide what to do w.r.t. configuration in a file
- Decide whether to add a randomized error strategy