![blamo!][blamologo]

>Does your website embed images from other domains?
>Are you suffering from [mixed content warnings]?
>Do I have just the thing for you!

Blamo is a webserver that will securely serve trusted, insecure content.

This project is a slight iteration of the design of GitHub's [camo].

## CLI

```sh
$ export BLAMO_KEY=$(blamo key generate)
$ blamo key decrypt $BLAMO_KEY $(blamo key encrypt $BLAMO_KEY "hello world")
hello world
$ blamo server run $BLAMO_KEY
listening on 8080...
```

## API

### `GET /v1/{token}`

The API is as simple as passing a single token, a [fernet] encrypted URL of the insecure content.
Everything else is configured ahead of time, including the shared key used to encrypt and decrypt tokens.

### Additional routes

* `GET /v1/_ready` - a readiness probe
* `GET /v1/_healthy` - a healthiness probe
* `GET /v1/_metrics` - a Prometheus metrics endpoint

[blamologo]: https://user-images.githubusercontent.com/343539/81590451-d06f1e80-9388-11ea-998e-9d83829a6d96.png
[mixed content warnings]: https://developer.mozilla.org/en-US/docs/Web/Security/Mixed_content
[camo]: https://github.com/atmos/camo
[fernet]: https://github.com/fernet/spec