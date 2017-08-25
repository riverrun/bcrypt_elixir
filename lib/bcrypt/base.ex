defmodule Bcrypt.Base do
  @moduledoc """
  Base module for the Bcrypt password hashing library.
  """

  use Bitwise

  @compile {:autoload, false}
  @on_load {:init, 0}

  def init do
    path = :filename.join(:code.priv_dir(:bcrypt_elixir), 'bcrypt_nif')
    :erlang.load_nif(path, 0)
  end

  @doc """
  Hash a password using Bcrypt.
  """
  def hash_password(password, salt) when is_binary(password) and is_binary(salt) do
    byte_size(salt) == 29 and hash(password, salt, :binary.part(salt, 1, 2)) ||
      raise ArgumentError, "The salt is the wrong length"
  end
  def hash_password(_, _) do
    raise ArgumentError, "The password and salt should be strings"
  end

  @doc """
  Generate a salt for use with Bcrypt.
  """
  def gensalt_nif(random, log_rounds, minor)
  def gensalt_nif(_, _, _), do: :erlang.nif_error(:not_loaded)

  @doc """
  Hash the password and salt with the Bcrypt hashing algorithm.
  """
  def hash_nif(password, salt)
  def hash_nif(_, _), do: :erlang.nif_error(:not_loaded)

  @doc """
  Verify the password by comparing it with the stored hash.
  """
  def checkpass_nif(password, stored_hash)
  def checkpass_nif(_, _), do: :erlang.nif_error(:not_loaded)

  defp hash(password, salt, prefix) when prefix in ["2a", "2b"] do
    hash_nif(:binary.bin_to_list(password), :binary.bin_to_list(salt))
    |> :binary.list_to_bin
  end
  defp hash(_, _, prefix) do
    raise ArgumentError, """
    Bcrypt does not support the #{prefix} prefix.
    For more information, visit the Comeonin wiki,
    at https://github.com/riverrun/comeonin/wiki.
    """
  end
end
