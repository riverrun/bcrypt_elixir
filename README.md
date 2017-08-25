# Bcrypt

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

## Installation

1. Add bcrypt_elixir to the `deps` section of your mix.exs file:

If you are using Erlang 20:

```elixir
def deps do
  [
    {:bcrypt_elixir, "~> 1.0"}
  ]
end
```

If you are NOT using Erlang 20:

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

### License

BSD. For full details, please read the LICENSE file.
