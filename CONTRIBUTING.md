# Contributing

Use British English and no em dashes. Preserve protocol identifiers. Keep admission,
identity links and local permissions separate. Every security change needs negative
fixtures and native-host verification where it affects host behaviour. Run the
protocol suite, Ruff, the native container script, package validation and
`git diff --check` before opening a pull request. Never add a production validation
bypass to make a demo pass. Review the versioned requirements coverage before
changing public behaviour.
