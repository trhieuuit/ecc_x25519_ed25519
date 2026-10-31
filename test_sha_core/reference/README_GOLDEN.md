# Golden reference RTL

These files are frozen reference implementations used only for functional verification of the unified SHA-2 core.

## Golden SHA-256

* sha256\_pkg.sv
* sha256\_core\_ref.sv

## Golden SHA-512 (Secworks snapshot)

* sha512\_k\_constants\_ref.sv
* sha512\_h\_constants\_ref.sv
* sha512\_w\_mem\_ref.sv
* sha512\_core\_ref.sv

## Rules

1. Do not modify these files while developing `sha2\_\*` RTL.
2. Do not include `reference/golden.f` in synthesis or implementation file lists.
3. Compile the golden files into a simulation-only library when doing side-by-side checking.
4. Compare block-by-block digests from the golden core against `sha2\_core`.
5. The active unified RTL is listed in `../rtl.f`.

## Note about Secworks constants

The unified implementation intentionally reuses separate active copies of
`sha512\_k\_constants.sv` and `sha512\_h\_constants.sv` in the parent directory.
The copies in this folder are frozen only to preserve the exact golden snapshot.

