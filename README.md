# Bcrypt

[![Build Status](https://travis-ci.com/riverrun/bcrypt_elixir.svg?branch=master)](https://travis-ci.com/riverrun/bcrypt_elixir)
[![Module Version](http://img.shields.io/hexpm/v/bcrypt_elixir.svg)](https://hex.pm/packages/bcrypt_elixir)
[![Hex Docs](https://img.shields.io/badge/hex-docs-lightgreen.svg)](https://hexdocs.pm/bcrypt_elixir/)
[![Total Download](https://img.shields.io/hexpm/dt/bcrypt_elixir.svg)](https://hex.pm/packages/bcrypt_elixir)
[![License](https://img.shields.io/hexpm/l/bcrypt_elixir.svg)](https://github.com/riverrun/bcrypt_elixir/blob/master/LICENSE)
[![Last Updated](https://img.shields.io/github/last-commit/riverrun/bcrypt_elixir.svg)](https://github.com/riverrun/bcrypt_elixir/commits/master)

Bcrypt password hashing library for Elixir.

Bcrypt is a well-tested password-based key derivation function that
can be configured to remain slow and resistant to brute-force attacks
even as computational power increases.

## Compatibility with other Bcrypt libraries

This version is based on the OpenBSD version of Bcrypt and supports
the `$2b$` and `$2a$` prefixes. For advice on how to use hashes with
the `$2y$` prefix, see [this issue](https://github.com/riverrun/comeonin/issues/103).

## Changes in version 2

In version 2.0, bcrypt_elixir has been updated to implement the Comeonin
and Comeonin.PasswordHash behaviours.

It now has the following two additional convenience functions:

* `add_hash/2`
  * same as `Comeonin.Bcrypt.add_hash/2` in Comeonin version 4
  * hashes a password and returns a map with the password hash
* `check_pass/3`
  * same as `Comeonin.Bcrypt.check_pass/3` in Comeonin version 4
  * takes a user struct and password as input and verifies the password

## Installation

1.  Add `:bcrypt_elixir` to the `deps` section of your `mix.exs` file:

    If you are using Erlang >20:

    ```elixir
    def deps do
      [
        {:bcrypt_elixir, "~> 2.0"}
      ]
    end
    ```

    If you are using Erlang 19 or below:

    ```elixir
    def deps do
      [
        {:bcrypt_elixir, "~> 0.12"}
      ]
    end
    ```

2.  Make sure you have a C compiler installed.
See the [Comeonin wiki](https://github.com/riverrun/comeonin/wiki/Requirements) for details.

3.  Optional: during tests (and tests only), you may want to reduce the number of rounds
so it does not slow down your test suite. If you have a config/test.exs, you should
add:

    ```elixir
    config :bcrypt_elixir, :log_rounds, 4
    ```

## Comeonin wiki

See the [Comeonin wiki](https://github.com/riverrun/comeonin/wiki) for more
information on the following topics:

* [Algorithms](https://github.com/riverrun/comeonin/wiki/Choosing-the-password-hashing-algorithm)
* [Requirements](https://github.com/riverrun/comeonin/wiki/Requirements)
* [Deployment](https://github.com/riverrun/comeonin/wiki/Deployment)
  * Including information about using Docker
* [References](https://github.com/riverrun/comeonin/wiki/References)

## Contributing

There are many ways you can contribute to the development of this library, including:

* Reporting issues
* Improving documentation
* Sharing your experiences with others
* [Making a financial contribution](#donations)

## Donations

First of all, I would like to emphasize that this software is offered
free of charge. However, if you find it useful, and you would like to
buy me a cup of coffee, you can do so at [PayPal](https://www.paypal.me/alovedalongthe).

### Documentation

http://hexdocs.pm/bcrypt_elixir

### License

BSD. For full details, please read the LICENSE file.
