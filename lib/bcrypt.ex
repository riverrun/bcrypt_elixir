defmodule Bcrypt do
  @moduledoc """
  """

  alias Bcrypt.{Base, Base64}

  @log_rounds 12

  @doc """
  Generate a salt for use with the `hashpass` function.

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

  To change the complexity (and the time taken) of the  password hash
  calculation, you need to change the value for `bcrypt_log_rounds`
  in the config file.
  """
  def hash_pwd_salt(password, opts \\ []) do
    Base.hash_password(password, Keyword.get(opts, :log_rounds, @log_rounds) |> gen_salt)
  end

  @doc """
  Check the password.

  The check is performed in constant time to avoid timing attacks.
  """
  def verify_hash(stored_hash, password) when is_binary(stored_hash) do
    Base.verify_hash(stored_hash, password)
  end
  def verify_hash(_, _) do
    raise ArgumentError, "Wrong type - the password and hash need to be strings"
  end

  @doc """
  Perform a dummy check for a user that does not exist.

  This always returns false. The reason for implementing this check is
  in order to make user enumeration by timing responses more difficult.
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
