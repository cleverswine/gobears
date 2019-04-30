# gobears

## Bearer token authentication handler for Go

This is a prototype/work in progress of a http handler that will inspect a Bearer token from the header, verify against specified scopes, and verify the signature by fetching and using the auth provider's signing key.

