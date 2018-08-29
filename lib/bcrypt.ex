defmodule Bcrypt do
  @moduledoc """
  Bcrypt password hashing library main module.

  This library can be used on its own, or it can be used together with
  [Comeonin](https://hexdocs.pm/comeonin/api-reference.html), which
  provides a higher-level api.

  For a lower-level API, see Bcrypt.Base.

  ## Bcrypt

  Bcrypt is a key derivation function for passwords designed by Niels Provos
  and David Mazières. Bcrypt is an adaptive function, which means that it can
  be configured to remain slow and resistant to brute-force attacks even as
  computational power increases.

  ## Bcrypt versions

  This bcrypt implementation is based on the latest OpenBSD version, which
  fixed a small issue that affected some passwords longer than 72 characters.
  By default, it produces hashes with the prefix `$2b$`, and it can check
  hashes with either the `$2b$` prefix or the older `$2a$` prefix.
  It is also possible to generate hashes with the `$2a$` prefix by running
  the following command:

      Bcrypt.Base.hash_password("hard to guess", Bcrypt.gen_salt(12, true))

  This option should only be used if you need to generate hashes that are
  then checked by older libraries.

  The `$2y$` prefix is not supported. For advice on how to use hashes with the
  `$2y$` prefix, see [this issue](https://github.com/riverrun/comeonin/issues/103).
  """

  alias Bcrypt.Base

  @doc """
  Generate a salt for use with the `Bcrypt.Base.hash_password` function.

  The log_rounds parameter determines the computational complexity
  of the generation of the password hash. Its default is 12, the minimum is 4,
  and the maximum is 31.

  The `legacy` option is for generating salts with the old `$2a$` prefix.
  Only use this option if you need to generate hashes that are then checked
  by older libraries.
  """
  def gen_salt(log_rounds \\ 12, legacy \\ false) do
    :crypto.strong_rand_bytes(16)
    |> Base.gensalt_nif(log_rounds, (legacy and 97) || 98)
  end

  @doc """
  Hash the password with a salt which is randomly generated.

  ## Configurable parameters

  The following parameters can be set in the config file:

    * `log_rounds` - the computational cost as number of log rounds, by default
      it is 12 (2^12).

  If you are hashing passwords in your tests, it can be useful to add
  the following to the `config/test.exs` file:

      config :bcrypt_elixir,
        log_rounds: 4

  NB. do not use this value in production.

  ## Options

  There is one option (this can be used if you want to override the
  value in the config):

    * `:log_rounds` - override the application's configured computational cost.
    * `:legacy` - whether to generate a salt with the old `$2a$` prefix. This
      should only be used to generate hashes that will be checked by older
      libraries.

  """
  def hash_pwd_salt(password, opts \\ []) do
    Base.hash_password(
      password,
      gen_salt(
        Keyword.get(opts, :log_rounds, Application.get_env(:bcrypt_elixir, :log_rounds, 12)),
        Keyword.get(opts, :legacy, false)
      )
    )
  end

  @doc """
  Check the password.

  The check is performed in constant time to avoid timing attacks.
  """
  def verify_pass(password, stored_hash) do
    Base.checkpass_nif(:binary.bin_to_list(password), :binary.bin_to_list(stored_hash))
    |> handle_verify
  end

  @doc """
  A dummy verify function to help prevent user enumeration.

  This always returns false. The reason for implementing this check is
  in order to make it more difficult for an attacker to identify users
  by timing responses.
  """
  def no_user_verify(opts \\ []) do
    hash_pwd_salt("password", opts)
    false
  end

  defp handle_verify(0), do: true
  defp handle_verify(_), do: false
end
