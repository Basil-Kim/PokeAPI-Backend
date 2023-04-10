
# Assignment 2 - JWT Login/Authentication Supertest
## Testing Requirements
- Test that the /register endpoint creates a new user in the database with the correct hashed password
- Test that the /login endpoint returns a JWT access token and refresh token for valid credentials
- Test that the /login endpoint throws a PokemonAuthError for invalid credentials
- Test that the /requestNewAccessToken endpoint returns a new JWT access token for a valid refresh token
- Test that the /requestNewAccessToken endpoint throws a PokemonAuthError for an invalid or missing refresh token
- Test that the refresh token is added to the refreshTokens array on login and removed on logout
- Test that the JWT access token can be decoded and contains the correct user data



- Test that a user can successfully register, login, and make a request with a JWT access token
- Test that an unauthenticated user cannot access protected endpoints
- Test that an expired JWT access token cannot be used to access protected endpoints
- Test that a request with an invalid JWT access token throws a PokemonAuthError
- Test that a refresh token cannot be used to access protected endpoints
- Test that a request with an invalid or missing refresh token throws a PokemonAuthError
- Test that non-admin user cannot access admin protected routes
- Test that after logging out, a user cannot access protected routes until the user re-login


//TODO: just this part is left to do
Also test error handling and edge cases, such as:

- Invalid payloads for register and login endpoints
- Invalid token secrets or expiration times
- Unhandled database errors
- Duplicate or missing documents in the database
- Invalid HTTP requests or responses