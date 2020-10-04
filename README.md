# Dockerfile Security
A collection of OPA rules to statically analyze Dockerfiles to improve security.

## Dockerfile Security best practices

The rules are a set of [security best practices as explained here](https://cloudberry.engineering/article/dockerfile-security-best-practices/).

## How to use

Rules are written in Rego language from [Open Policy Agent](https://www.openpolicyagent.org/)

You can use [conftest](https://conftest.dev) in your CI/CD pipeline to analyze Dockerfiles:

```
conftest test --policy dockerfile-security.rego Dockerfile
```

Example output:

```
conftest test --policy dockerfile-security.rego  Dockerfile
FAIL - Dockerfile - Do not run as root, use USER instead
FAIL - Dockerfile - Line 0: use a trusted base image
FAIL - Dockerfile - Line 6: Use COPY instead of ADD
FAIL - Dockerfile - Line 8: Do not use 'sudo' command

8 tests, 4 passed, 0 warnings, 4 failures, 0 exceptions
```


