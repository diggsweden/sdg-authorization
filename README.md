![Logo](docs/images/digg.png)

# OAuth2 and OpenID Connect Samples

In the `samples` directory we supply a set of different example applications that illustrate
how to manage OAuth2 and OpenID Connect within the Swedish SDG framework. 

The applications are:

- ["Förhandsgranskningstjänsten"](samples/forhandsgranskning/README.md) - The preview application to which
the user logs on (using OpenID connect). The application later makes calls to different "bevistjänster".
For this it needs authorization and obtains access tokens from the Authorization Server.

- ["Bevistjänst"](samples/bevistjanst/README.md) - An example API-service that consumes the access tokens
issued by the Authorization Server on request by the "Förhandsgranskningstjänst".

Sequence diagrams:

- ["Usecases"](docs/sequence.md) - Sequence diagrams for retrieving an access token from the Authorization 
  Server.