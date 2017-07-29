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

```elixir
def deps do
  [
    {:bcrypt_elixir, "~> 0.12"}
  ]
end
```

You also need to have a C compiler installed to run bcrypt_elixir.
See the [Comeonin wiki](https://github.com/riverrun/comeonin/wiki) for details.

## Use

In most cases, you will just need to use the following three functions:

* hash_pwd_salt - hash a password with a randomly-generated salt
* verify_pass - check the password by comparing it with a stored hash
* no_user_verify - perform a dummy check to make user enumeration more difficult

See the documentation for the Bcrypt module for more information.

For a lower-level api, see the documentation for Bcrypt.Base.

### License

BSD. For full details, please read the LICENSE file.
