# Bcrypt

[![Patreon](https://img.shields.io/badge/patreon-donate-brightgreen.svg)](https://www.patreon.com/riverrun)
[![Hex.pm Version](http://img.shields.io/hexpm/v/bcrypt_elixir.svg)](https://hex.pm/packages/bcrypt_elixir)

Bcrypt password hashing algorithm for Elixir.

Bcrypt is a well-tested password-based key derivation function that
can be configured to remain slow and resistant to brute-force attacks
even as computational power increases.

This version is based on the OpenBSD version of Bcrypt and supports
the `$2b$` and `$2a$` prefixes. For advice on how to use hashes with
the `$2y$` prefix, see [this issue](https://github.com/riverrun/comeonin/issues/103).

This library can be used on its own, or it can be used together
with [Comeonin](https://hexdocs.pm/comeonin/api-reference.html),
which provides a higher-level api.

## Async tests issue

Some developers have reported problems when running tests using `async: true`
with version 1.0 of bcrypt_elixir. See this [issue](https://github.com/riverrun/bcrypt_elixir/issues/10)
for more details.

## Installation

1. Add bcrypt_elixir to the `deps` section of your mix.exs file:

If you are using Erlang >20:

```elixir
def deps do
  [
    {:bcrypt_elixir, "~> 1.1"}
  ]
end
```

If you are NOT using Erlang 19 or below:

```elixir
def deps do
  [
    {:bcrypt_elixir, "~> 0.12"}
  ]
end
```

2. Make sure you have a C compiler installed.
See the [Comeonin wiki](https://github.com/riverrun/comeonin/wiki) for details.

3. Optional: during tests (and tests only), you may want to reduce the number of rounds
so it does not slow down your test suite. If you have a config/test.exs, you should
add:

```elixir
config :bcrypt_elixir, :log_rounds, 4
```

## Use

In most cases, you will just need to use the following three functions:

* hash_pwd_salt - hash a password with a randomly-generated salt
* verify_pass - check the password by comparing it with a stored hash
* no_user_verify - perform a dummy check to make user enumeration more difficult

See the documentation for the Bcrypt module for more information.

For a lower-level api, see the documentation for Bcrypt.Base.

For further information about password hashing and using Bcrypt with Comeonin,
see the Comeonin [wiki](https://github.com/riverrun/comeonin/wiki).

### Docker

In order to use `bcrypt_elixir` in Docker, you will probably need to manually compile it in your Dockerfile. In order to do it on the Alpine image, you're going to need `make`, `gcc` and `libc-dev`. Add the following lines to your Dockerfile, right after `RUN mix deps.get`

```
RUN apk add --no-cache make gcc libc-dev
```

Remember to add your local `_build` and `deps` folders to `.dockerignore`, because otherwise, you'll see errors coming up.

### Deployment

See the Comeonin [deployment guide](https://github.com/riverrun/comeonin/wiki/Deployment).

## Contributing

There are many ways you can contribute to the development of this library, including:

* reporting issues
* improving documentation
* sharing your experiences with others
* [making a financial contribution](#donations)

## Donations

You can support the ongoing maintenance of this project by
[making donations through Patreon](https://www.patreon.com/riverrun).

Patreon, by default, will bill you on a monthly basis. If you prefer to make a one-off payment,
see [this guide](https://support.patreon.com/hc/en-us/articles/204606215-Can-I-make-a-one-time-payment-).

### License

BSD. For full details, please read the LICENSE file.
