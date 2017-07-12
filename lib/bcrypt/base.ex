defmodule Bcrypt.Base do
  @moduledoc """
  Base module for the Bcrypt password hashing library.
  """

  use Bitwise
  alias Bcrypt.{Base64, Tools}

  @salt_len 16

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
    hashpw(:binary.bin_to_list(password), :binary.bin_to_list(salt))
  end
  def hash_password(_, _) do
    raise ArgumentError, "The password and salt should be strings and " <>
      "the salt (before encoding) should be 16 bytes long"
  end

  @doc """
  Verify a password by comparing it with the stored Bcrypt hash.
  """
  def verify_pass(password, stored_hash) do
    hashpw(:binary.bin_to_list(password), :binary.bin_to_list(stored_hash))
    |> Tools.secure_check(stored_hash)
  end

  @doc """
  Initialize the P-box and S-box tables with the digits of Pi,
  and then start the key expansion process.
  """
  def bf_init(key, key_len, salt)
  def bf_init(_, _, _), do: :erlang.nif_error(:not_loaded)

  @doc """
  The main key expansion function.
  """
  def bf_expand0(state, input, input_len)
  def bf_expand0(_, _, _), do: :erlang.nif_error(:not_loaded)

  @doc """
  Encrypt and return the hash.
  """
  def bf_encrypt(state)
  def bf_encrypt(_), do: :erlang.nif_error(:not_loaded)

  defp hashpw(password, salt) do
    [prefix, log_rounds, salt] = Enum.take(salt, 29) |> :string.tokens('$')
    bcrypt(password, salt, prefix, log_rounds)
    |> fmt_hash(salt, prefix, zero_str(log_rounds))
  end

  defp bcrypt(key, salt, prefix, log_rounds) when prefix in ['2b', '2a'] do
    key_len = if prefix == '2b' and length(key) > 72, do: 73, else: length(key) + 1
    {salt, rounds} = prepare_keys(salt, List.to_integer(log_rounds))
    bf_init(key, key_len, salt)
    |> expand_keys(key, key_len, salt, rounds)
    |> bf_encrypt
  end
  defp bcrypt(_, _, prefix, _) do
    raise ArgumentError, "Bcrypt does not support the #{prefix} prefix"
  end

  defp prepare_keys(salt, log_rounds) when log_rounds in 4..31 do
    {Base64.decode(salt), bsl(1, log_rounds)}
  end
  defp prepare_keys(_, _) do
    raise ArgumentError, "Wrong number of rounds"
  end

  defp expand_keys(state, _key, _key_len, _salt, 0), do: state
  defp expand_keys(state, key, key_len, salt, rounds) do
    bf_expand0(state, key, key_len)
    |> bf_expand0(salt, @salt_len)
    |> expand_keys(key, key_len, salt, rounds - 1)
  end

  defp zero_str(log_rounds) do
    if log_rounds < 10, do: "0#{log_rounds}", else: "#{log_rounds}"
  end

  defp fmt_hash(hash, salt, prefix, log_rounds) do
    "$#{prefix}$#{log_rounds}$#{Base64.normalize(salt)}#{Base64.encode(hash)}"
  end
end
