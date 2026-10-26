# Differences of fake-pdp from the published site

This file lists the places where the tool `fake-pdp` differs from the page `docs/tools.html`. The code does not change the site. The owner updates the site later. The numbers continue the list of `site-differences.md` in spirit, but this file has its own numbers.

## Command line

1. The page shows `fake-pdp 1.0 on ...`. The program shows the version of the crate, which is `0.1.0` in the workspace. The program prints `fake-pdp <version> on http://<address>`.
2. The page shows only the flag `--listen`. The program has six more flags: `--clock-start`, `--admin`, `--credential-file`, `--failures`, `--workers` and `--print-config`. The page says that the clock and the failures are in the data file. This is also true. The flags add the controls that the closed data schema cannot hold.
3. The page shows `--listen` as optional and gives no default. The default is `127.0.0.1:8181`.
4. The common rules of the page list `--format text|json` for each tool. The program has no `--format` option. Its output is the log of the questions.
5. The page lists the exit codes 0 and 2. The program also uses the exit code 1 when it cannot open the port. The common rules of the page give the code 1 to "a problem in the input or in the implementation", which is close.
6. The signals SIGINT, SIGTERM and SIGHUP stop the program with the exit code 0. The page says "stopped on request".

## Data file

7. The page does not show the data file format. The format is the schema `fake-pdp-data`. That schema is closed. It has no member `admin`, no member `credential_file` and no failure kind `close`, `invalid_json` or `no_units`.
8. The admin endpoints are on with the flag `--admin`, not with a member `admin` of the data file. The credential of the PEP comes from the flag `--credential-file`, not from a member of the data file. The schema has `credential_sha256` for each service, and the program uses it.
9. The failure kinds `close`, `invalid_json` and `no_units` come from the file of the flag `--failures` and from the admin endpoint. The data file keeps the kinds `error_503`, `delay` and `no_answer`.
10. The schema says that a metadata member that the file does not give is not in the metadata. The program always publishes the four members `procurauth_usage_max_seconds`, `procurauth_idle_max_seconds`, `procurauth_evaluations_max_bytes` and `procurauth_evaluations_max_items`. It uses the default values of the README. Paragraphs 6.9, 10.7 and 10.7a say that a PDP publishes these values, and the program enforces them.
11. A counter of the data file names no service. The program applies it to each service whose document declares the budget. A counter for a budget that no service declares has no effect.

## Log

12. The page shows the limits as `{"max_rows":5000,"max_duration":30}`. The program sorts the members by name, because the answer is a sorted JSON object.
13. The program adds `units N` after the limits of a counted `true` answer. It adds `fault KIND` when it made a failure. A `false` answer shows its reason, and `retry_after` when it has one.
14. The page shows `key/minute 99`. The word `key` is the key of the question. The program names the limit as well, for example `alice/writes/second 9`, when one question touches more than one budget.
15. The list of counters starts a new line after 60 columns. The new line aligns under the first counter.

## Behaviour that the page does not describe

16. The program keeps the last 10,000 questions in memory with full values. The admin endpoint `GET /__fake/log` gives them.
17. The program checks the credential of a service as a SHA-256 digest (12). It answers `invalid_resource` for a question about another service than the service of the credential.
18. A body above `procurauth_evaluations_max_bytes` gets HTTP 413. More items than `procurauth_evaluations_max_items` get HTTP 400. See `decisions-fake-pdp.md`.
