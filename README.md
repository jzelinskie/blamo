![blamo!][blamologo]

>Does your website embed images from other domains? Are you suffering from [mixed content warnings]? Do I have just the thing for you!

Blamo is a webserver that will securely serve trusted, insecure content.

This project is a slight iteration of the design of GitHub's [camo].

## API

### `GET /v1/{token}`

The API is as simple as passing a single token, a [fernet] encrypted URL of the insecure content. Everything else is configured ahead of time, including the shared key used to encrypt and decrypt tokens.

### Additional routes

* `GET /v1/_healthy` implements a healthiness probe
* `GET /v1/_ready` implements a readiness probe
* `GET /v1/_metrics` implements a Prometheus metrics endpoint

[blamologo]: https://user-images.githubusercontent.com/343539/81027263-0e30ec00-8e4b-11ea-8402-b097654a81ae.png
[mixed content warnings]: https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content
[camo]: https://github.com/atmos/camo
[fernet]: https://github.com/fernet/spec
