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
  def hash_password(password, salt)
      when is_binary(password) and is_binary(salt) and byte_size(salt) == 29 do
        #hashpw(:binary.bin_to_list(password), :binary.bin_to_list(salt))
    hash_nif(password, salt) |> :binary.list_to_bin
  end
  def hash_password(_, _) do
    raise ArgumentError, "The password and salt should be strings and " <>
      "the salt (before encoding) should be 16 bytes long"
  end

  @doc """
  """
  def gensalt_nif(random, log_rounds)
  def gensalt_nif(_, _), do: :erlang.nif_error(:not_loaded)

  @doc """
  """
  def hash_nif(password, salt)
  def hash_nif(_, _), do: :erlang.nif_error(:not_loaded)

  @doc """
  """
  def checkpass_nif(password, stored_hash)
  def checkpass_nif(_, _), do: :erlang.nif_error(:not_loaded)
end
