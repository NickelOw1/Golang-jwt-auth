# Golang jwt auth
Golang jwt auth is a part of authorization service, developed with Golang, JWT and MongoDB

# Endpoints overview

## POST /gettokens
This endpoint receives user GUID from query params, generates access and refresh tokens, sets cookie with refresh token.

## GET /refreshtokens
This endpoint receives refresh token from cookies, verifies it and generates new pair of access-refresh tokens.
