<h1 align="center">Threshold BLS</h1>

**<p style="text-align: center;">Work In Progress</p>**

## Overview

A fork of https://github.com/celo-org/celo-threshold-bls-rs that was modified as following:
- Supports only BLS12-381.
- Solidity, WASM binding and CLI were removed.
- dkg-core was merged into threshold-bls.

In addition, the DKG protocol was modified to use a simpler complaint phase.
<!--- TODO: describe the modified protocol --->

## Build Guide

Build with `cargo build (--release)`.

Test with `cargo test`.

Benchmark with `cargo bench`.

## Disclaimers

**This software has not been audited. Use at your own risk.**
