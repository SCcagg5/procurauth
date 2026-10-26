# Differences from the published site: keycheck

This file lists the places where `keycheck` differs from the section `keycheck` of `docs/tools.html`, or where the page says nothing. The tool does not change the site. The owner updates the site later. The items 13 to 15 of `site-differences.md` also concern `keycheck`.

## Output

1. The page gives the line of a bad key: `bad: length (expected 53 characters, found 47)`. The tool prints exactly this line. It does not give the lines of a good key. The tool prints three lines: `good`, `sha256: <digest>` and `hint: <hint>`.
2. The page does not describe the JSON form. The tool prints one object on one line. The shape is in the README of the crate and in `schemas/keycheck-output.schema.json`. This schema is new. The page lists five schemas, and `site-differences.md` lists eight.
3. The page says that the digest is in hexadecimal. The tool uses lower-case digits.

## Exit codes

4. The page says that exit code 2 is a usage error. The tool also gives 2 for an input that it cannot read. The input is a format file that is absent, too long or not valid. It can also be a standard input that is empty, too long or not UTF-8.
5. The page does not say what an empty input gives. The tool gives exit code 2, because an empty input is not a text to check. A text of one character or more that is not a key gives exit code 1.
6. The page does not say what an input that is not UTF-8 gives. The tool gives exit code 2. The checker of the core works on text, and the alphabet of a format has printable ASCII characters only.

## Input rules that the page does not give

7. The tool reads at most 4096 bytes of the standard input, and at most 65536 bytes of the format file.
8. The tool removes exactly one line end at the end of the input: `\n` or `\r\n`. It does not trim spaces. A second line or a space makes the text bad.

## Version and help

9. The page says that `--version` shows the version and the licence. The tool prints `keycheck <version>` and a second line, `Apache-2.0`.
10. The tool also accepts `-h` and `-V`. The page lists the long flags only.

## Secrecy

11. The page says that the tool never writes the text to a log. The tool goes further. A usage error never shows the text of an argument, and no message shows the path of the format file. Each of them can be a key that the user gave by mistake.
12. A finding about the format file repeats the value that it found. The tool replaces each run of more than 24 characters without a space by `<N characters hidden>`. A user can give a key as the format file by mistake.
13. The configuration rules say that an error message names the value. This does not apply to the arguments of the command line, for the reason in item 11. It applies to the members of the format file.
