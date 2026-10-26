# access-lint

`access-lint` checks the action document of a ProcurAuth service before the service publishes it. It can also check a file of grants against the document. It can also check an answer of the options route.

The tool is a Rust program with a small library. It reads its input from files, or from an `http` URL for the document. It reads no environment variable.

## Usage

```text
access-lint [--format text|json] [--grants FILE] [--options FILE] <document>
```

| Argument | Meaning |
| --- | --- |
| `<document>` | The action document. It is a file or an `http` URL. |
| `--format text\|json` | The form of the output. The default is `text`. |
| `--grants FILE` | A file of grants. The tool checks each limit value against the document. |
| `--options FILE` | A file with an answer of the options route. |
| `--help` | Show the usage and exit with 0. |
| `--version` | Show the version and the licence `Apache-2.0`, and exit with 0. |

The command line is closed. An unknown option, or an option that occurs two times, is a usage error.

## Example

```text
$ access-lint actions.json
actions.json: 2 errors
  $.actions[1].limits[2]  rule 5.2  undeclared limit
  $.limits[0].min         rule 6.1  budget with "min"
$ echo $?
1
```

Each finding has one line: the JSON path of the member, the paragraph of the protocol and a short text. A warning has the mark `warning:` before its text. The JSON output also has the code of the finding and a full message that names the value.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | No error. The input can have warnings. |
| 1 | At least one error in an input. |
| 2 | Usage error, or an input that the tool cannot read. |

A warning shows a SHOULD of the protocol, a size above the minimum of 5.3c, or a value that has no effect. A warning does not change the exit code. The text output counts the warnings in the head line.

## The document

The tool checks the action document with the rules of 5.2, 5.3, 5.3c, 6.1 and 7.1. The core library reads the document. It lists every problem, and not only the first one.

When the argument starts with `http://`, the tool fetches it with one GET request. It reads at most 64 KiB, which is the minimum of 5.3c. It stops after 10 seconds. It follows at most 3 redirects, and only to the same host and port. It does not read the environment for a proxy.

The tool has no TLS code. It refuses an `https` URL with exit code 2. Save the document to a file, or use a local `http` address.

## The file of grants

The file is a JSON object with one member, `grants`. This member is a list of the grants of one subject. A grant has `action`, `resource` and optionally `limits`, as in the data of `fake-pdp`. The schema is `schemas/grants-file.schema.json`.

```json
{
  "grants": [
    { "action": "access", "resource": "service:datastore",
      "limits": { "requests": [ { "amount": 10, "window": "second" } ] } },
    { "action": "data.read", "resource": "service:datastore/host:prod/database:test1",
      "limits": { "max_rows": 1000 } }
  ]
}
```

The tool checks each grant against the document: the service, the tree of types, the action and its types. It checks each value against the declaration of its limit: the kind, the range of a ceiling, the windows of a budget. A value for a limit that the document does not declare gives a warning (6.10). A budget value on a grant other than `access` on the service gives a warning (8.3).

## The options file

The file is the answer of the options route (5.8). Its schema is `schemas/options-route-answer.schema.json`. The tool checks the members, the ids, the size and the number of items.

The file can also be an envelope with two members: `query` and `answer`. The `query` is the query string of the request, without the question mark, as 5.7 says. The tool then checks the parameters. It checks the type and the parent against the document. It checks that the answer has no more items than `limit`. The schema is `schemas/options-file.schema.json`.

```json
{
  "query": "parent=host%3Aprod&type=database&limit=2",
  "answer": { "items": [ { "id": "test1", "label": "test1", "has_children": false } ], "next": null }
}
```

## Rules

The file `RULES.md` lists each rule with its paragraph, its code and its severity. The schema of the JSON output is `schemas/access-lint-output.schema.json`.

## Build and test

Use Docker. Do not install Rust on the host.

```text
scripts/cargo.sh build --release -p access-lint
scripts/cargo.sh test -p access-lint
```

Each rule has a bad fixture and a good fixture in `tests/fixtures/`. The tests named `p_<paragraph>_...` check one rule each. The files in `tests/golden/` hold the expected output.
