# keycheck

`keycheck` checks the text of a key against a key format. It is a tool of ProcurAuth. It uses no store and no network.

The protocol defines no format for the text of a key (3.8). The system that makes the keys chooses the format. For this reason, the format is an input of the tool.

## Usage

```text
keycheck [--format text|json] <format-file>
```

The tool reads the text of the key on the standard input. It never reads the text from an argument.

| Argument | Meaning |
| --- | --- |
| `<format-file>` | The file of the key format. It is a JSON document. |
| `--format text` | Print lines of text. This is the default. |
| `--format json` | Print one JSON object on one line. |
| `--help` | Show the usage and exit with 0. |
| `--version` | Show the version and the licence line `Apache-2.0`, and exit with 0. |

The tool reads no environment variable and no other file. It makes no network call. Each flag occurs one time at most.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | The text is a good key. Help and version also exit with 0. |
| 1 | The text is not a key of the format. |
| 2 | The command line is not valid, or the tool cannot read an input. |

The result goes to the standard output. The diagnostics go to the standard error. The tool never uses colour.

## The format file

The format file has the members `prefix`, `length`, `alphabet` and `checksum`. The schema is `schemas/key-format.schema.json`. The file `examples/format.json` is the format of the portal.

```json
{
  "prefix": "mcp_",
  "length": 53,
  "alphabet": "A-Za-z0-9",
  "checksum": { "algorithm": "crc32", "encoding": "base62", "characters": 6 }
}
```

This format means 4 characters of prefix, 43 random characters and 6 characters of CRC-32 in base62. The total is 53 characters. The member `checksum.covers` is optional. Its default is `random`.

The reader of the format file is strict. An unknown member, a duplicate member, a wrong type and a contradiction between two members stop the tool with exit code 2. Each problem has one line on the standard error. The line gives the JSON path, the rule, the expected value and the value found.

The tool reads at most 65536 bytes of the format file.

## Examples

A good key:

```text
$ keycheck format.json < key.txt
good
sha256: a9985ef98e018b4c34f4e5cedd1e19cb5b31e533f30a18fc12834f378919b99f
hint: aB3d
$ echo $?
0
```

The digest is the SHA-256 of the whole text, in lower-case hexadecimal. The hint is at most 4 of the first characters of the random part.

A bad key:

```text
$ keycheck format.json < key.txt
bad: length (expected 53 characters, found 47)
$ echo $?
1
```

The tool gives the first cause. The checks run in this order: prefix, length, alphabet, checksum. The four causes are `prefix`, `length`, `alphabet` and `checksum`.

| Cause | Text |
| --- | --- |
| `prefix` | `bad: prefix (expected the prefix mcp_)` |
| `length` | `bad: length (expected 53 characters, found 47)` |
| `alphabet` | `bad: alphabet (the character at position 11 is not in the alphabet A-Za-z0-9)` |
| `checksum` | `bad: checksum (the checksum characters do not match the text)` |

## JSON output

The flag `--format json` prints one object on one line, and then a line end. The members keep a fixed order. The schema is `schemas/keycheck-output.schema.json`.

A good key:

```json
{"verdict":"good","sha256":"a9985ef98e018b4c34f4e5cedd1e19cb5b31e533f30a18fc12834f378919b99f","hint":"aB3d"}
```

A bad key:

```json
{"verdict":"bad","cause":"length","message":"length (expected 53 characters, found 47)","detail":{"expected":53,"found":47}}
```

| Member | Content |
| --- | --- |
| `verdict` | `good` or `bad`. |
| `sha256` | Only for `good`. The digest of the text. |
| `hint` | Only for `good`. At most 4 characters. |
| `cause` | Only for `bad`. `prefix`, `length`, `alphabet` or `checksum`. |
| `message` | Only for `bad`. The text that the text form prints after `bad: `. |
| `detail` | Only for `bad`. An object that depends on the cause. |

The object `detail` has `expected` for `prefix`. It has `expected` and `found` for `length`. It has `position` and `alphabet` for `alphabet`. It is empty for `checksum`.

## The standard input

- The tool reads at most 4096 bytes. An input that is longer gives exit code 2.
- The tool removes exactly one line end at the end: `\n` or `\r\n`. A second line end stays in the text, and the text is bad.
- An input with no text, or with only one line end, gives exit code 2.
- An input that is not UTF-8 gives exit code 2.
- A space, a second line or a character that is not in the alphabet makes the text bad. The tool does not trim the text.

## Secrecy

The text of a key is a secret. The tool never prints it, never writes it to a log, and never puts it in an error message.

A usage error does not show the text of an argument. A user can give a key as an argument by mistake. The message tells the user that the tool hides the argument. For the same reason, the tool does not show the path of the format file.

A finding about the format file repeats the value that it found. The tool replaces each run of more than 24 characters without a space by `<N characters hidden>`. A user can give the text of a key as the format file by mistake.

The tests make keys, feed bad variants through each failure mode, and search each output for the key.

## Library

The crate has a library. The function `keycheck::run(args, stdin, stdout, stderr)` does all the work and returns an `Exit` value. The binary only calls it. A test can call it without a process.

The checker is `procurauth_core::key_format::KeyFormat::check` of the core crate.

## Test

Run the tests in Docker.

```text
scripts/cargo.sh test -p keycheck
```

A test that has a paragraph of the protocol has a name that starts with the paragraph, for example `p_3_8_text_bad_prefix`.
