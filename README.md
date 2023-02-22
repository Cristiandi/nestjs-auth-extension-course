# NestJS - Authentication and Authorization
## JWT (JSON Web Token)
Are an open starndard used to share security information between two parties. A client and a server. Each JWT contains encoded JSON objects, including a set of claims, JWTs are signed using a cryptographic algorithm to ensure that claims cannot by altered after the token has been issued. JWTs can be signed using a secret with the HMAC algorithm or a public/private key using RSA or ECDSA. 
JWTs consist of three parts, separated by dots (.), which are: Header, Payload, Signature.
## Refresh Token
A refresh token is special token used to obtain new access tokens. this allow us to have short lived access tokens without forcing users to manually login every time the token expires. Once the access token expires, client aplications can use a refresh token to "refresh", aka "regenerate" or "retrive" a new access token behind the scenes. refresh token should returned alongside the access token and or ID token as part of the user's intial authentication and authorization flow. After that applications must then securely store the refresh tokens. You can think of a refresh token as if it were a user's credentials set. As is does let them re authenticate.
## Refresh token rotation
Whenever a refresh token was used to issue a new pair of tokens, we'll invalidate the original one (or old refresh token) so it can't be used again in the future. To do all of this, we're going to add a Redis database to our stack.
## Automatic reuse detection
This is a security feature that prevents a refresh token from being used more than once. This is done by storing a record of the refresh token in the database. When a refresh token is used to issue a new pair of tokens, we'll invalidate the original one (or old refresh token) so it can't be used again in the future. To do all of this, we're going to add a Redis database to our stack.
## Role-based access control (RBAC)
Is a policy-neutral access-control mechanism defined around roles and privileges. 
## Claim based authorization
Represents what the subject can do, not what the subject is. When implementing claims-based authorization, instead of defining a set of roles that can be assigned to users, we define multiple permissions and then have the ability to grant those permissions to individual users.