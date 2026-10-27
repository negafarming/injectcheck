# Security policy

## Reporting a problem in injectcheck

If you find a vulnerability in injectcheck itself, for example a way for a suite file or a model's output to leak an API key or run code, report it privately. Use the Security tab's private vulnerability reporting if it is enabled for the repository, and otherwise contact the maintainer directly. Please don't open a public issue for it. Include the version, the command you ran and the output.

## Responsible use

injectcheck sends adversarial prompts to the endpoints you configure. Only point it at systems you are authorized to test. The bundled payloads are harmless by design, and custom suites should stay that way: canary strings and reserved example domains, not harmful content.

API keys are read from environment variables. Keep them out of shell history and out of suite files, and use your CI provider's secret store in pipelines.
