#!/usr/bin/env -S just --justfile

alias t := test

test:
	RUST_LOG=debug cargo test -- --test-threads=1