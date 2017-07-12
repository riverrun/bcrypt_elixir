defmodule Bcrypt do
  @moduledoc """
  Bcrypt password hashing library main module.

  For a lower-level API, see Bcrypt.Base.

  ## Bcrypt

  Bcrypt is a key derivation function for passwords designed by Niels Provos
  and David Mazières. Bcrypt is an adaptive function, which means that it can
  be configured to remain slow and resistant to brute-force attacks even as
  computational power increases.

  The computationally intensive code is run in C, using Erlang NIFs. One concern
  about NIFs is that they block the Erlang VM, and so it is better to make
  sure these functions do not run for too long. This bcrypt implementation
  has been adapted so that each NIF runs for as short a time as possible.

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
  """

  alias Bcrypt.{Base, Base64}

  @log_rounds 12

  @doc """
  Generate a salt for use with the `Bcrypt.Base.hash_password` function.

  The log_rounds parameter determines the computational complexity
  of the generation of the password hash. Its default is 12, the minimum is 4,
  and the maximum is 31.

  The `legacy` option is for generating salts with the old `$2a$` prefix.
  Only use this option if you need to generate hashes that are then checked
  by older libraries.
  """
  def gen_salt(log_rounds \\ @log_rounds, legacy \\ false)
  def gen_salt(log_rounds, _) when not is_integer(log_rounds) do
    raise ArgumentError, "Wrong type - log_rounds should be an integer between 4 and 31"
  end
  def gen_salt(log_rounds, legacy) when log_rounds in 4..31 do
    :crypto.strong_rand_bytes(16)
    |> :binary.bin_to_list
    |> fmt_salt(zero_str(log_rounds), legacy)
  end
  def gen_salt(log_rounds, legacy) when log_rounds < 4, do: gen_salt(4, legacy)
  def gen_salt(log_rounds, legacy) when log_rounds > 31, do: gen_salt(31, legacy)

  @doc """
  Hash the password with a salt which is randomly generated.

  ## Options

  There is one option:

    * log_rounds - the number of log rounds
      * the default is 12

  """
  def hash_pwd_salt(password, opts \\ []) do
    Base.hash_password(password, Keyword.get(opts, :log_rounds, @log_rounds) |> gen_salt)
  end

  @doc """
  Check the password.

  The check is performed in constant time to avoid timing attacks.

  ## Options

  There are no options.
  """
  def verify_pass(password, stored_hash, opts \\ [])
  def verify_pass(password, stored_hash, _) when is_binary(password) do
    Base.verify_pass(password, stored_hash)
  end
  def verify_pass(_, _, _) do
    raise ArgumentError, "Wrong type - the password should be a string"
  end

  @doc """
  A dummy verify function to help prevent user enumeration.

  This always returns false. The reason for implementing this check is
  in order to make it more difficult for an attacker to identify users
  by timing responses.
  """
  def no_user_verify(opts) do
    hash_pwd_salt("password", opts)
    false
  end

  defp zero_str(log_rounds) do
    if log_rounds < 10, do: "0#{log_rounds}", else: "#{log_rounds}"
  end

  defp fmt_salt(salt, log_rounds, false), do: "$2b$#{log_rounds}$#{Base64.encode(salt)}"
  defp fmt_salt(salt, log_rounds, true), do: "$2a$#{log_rounds}$#{Base64.encode(salt)}"
end
