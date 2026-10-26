# Differences of access-lint from the published site

This file lists the places where `access-lint` differs from the section `access-lint` of `docs/tools.html`. The tool does not change the site. The owner updates the site later.

## Output

1. The site example shows lines with a path, a rule and a short text. The tool prints exactly this form for an error. The example of the site is a golden test.
2. The site does not show a warning. The tool prints a warning in the same form, with the mark `warning:` before the short text. A warning never makes the exit code 1.
3. The head line shows the number of errors, as the site does. The tool adds the number of warnings when it is not 0. It prints `no finding` when the input has neither.
4. The text output shows a short text of the rule, as the site does. The full message with the name and the value is in the JSON output, in the member `message`.
5. The tool has no option to make a warning fail. The site shows no such option. A later version can add one.
6. With `--grants` or `--options`, the tool prints one head line and one block for each input. The block of the document comes first.
7. The JSON output is not on the site. Its schema is `schemas/access-lint-output.schema.json`.

## Rules

8. The site lists the rules 5.2, 5.3, 5.8, 6.1 and 7.1. The tool also uses 3.5, 4.1, 4.2, 5.3c, 5.7, 6.10, 7.3 and 8.3. `crates/access-lint/RULES.md` lists each rule.
9. Four checks are new. They are `budget_name_window` (6.1), `duplicate_budget_value` (8.3), `duplicate_id` (4.2) and `has_children_without_types` (5.8). Each is a warning, because the protocol does not say that the input is bad.
10. The check `duplicate_id` reads 4.2 as "the ids of the children of one node are unique". The protocol does not say it in a MUST sentence.

## Input

11. The site says that the input can be a URL. The tool fetches an `http` URL only. It has no TLS code, so it refuses an `https` URL with exit code 2.
12. The URL is the full URL of the document. The tool does not add the path `/.well-known/procurauth/actions` of 5.1.
13. A fetch reads at most 64 KiB, stops after 10 seconds and follows at most 3 redirects to the same host and port. A larger body, a status other than 200 and a redirect to another host give exit code 2.
14. A file can have up to 8 MiB. The tool gives a warning for a document above 64 KiB (5.3c). A URL cannot give more than 64 KiB.
15. The site does not define the file of grants. The tool reads a JSON object with the member `grants`. Its items have the shape of a grant of `fake-pdp-data`. The schema is `schemas/grants-file.schema.json`.
16. The file of grants holds the grants of one subject. This lets the tool check that a subject has one value for each budget (8.3).
17. The site says only "an answer of the options route". The tool reads this answer. It also reads an envelope with the members `query` and `answer`, so that it can check the query (5.7) against the document. The schema is `schemas/options-file.schema.json`.
18. The answer of the options route does not name the type of its items. Without the `query`, the tool cannot check the type or the parent. It checks the members and the bounds of 5.8.

## Command line

19. `--version` prints two lines: the name with the version, and the licence `Apache-2.0`.
20. The tool does not read the standard input, because the site does not say that `access-lint` does.
21. The tool reads no environment variable. This includes the variables for an HTTP proxy.
