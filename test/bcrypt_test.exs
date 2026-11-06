defmodule BcryptTest do
  use ExUnit.Case
  doctest Bcrypt

  import Comeonin.BehaviourTestHelper

  test "implementation of Comeonin.PasswordHash behaviour" do
    password = Enum.random(ascii_passwords())
    assert correct_password_true(Bcrypt, password)
    assert wrong_password_false(Bcrypt, password)
  end

  test "Comeonin.PasswordHash behaviour with non-ascii characters" do
    password = Enum.random(non_ascii_passwords())
    assert correct_password_true(Bcrypt, password)
    assert wrong_password_false(Bcrypt, password)
  end

  test "large passwords are converted only up to the bytes the NIF reads" do
    password = String.duplicate("a", 1_000_000)
    hash = Bcrypt.hash_pwd_salt(password, log_rounds: 4)

    heap_words =
      Task.async(fn ->
        assert Bcrypt.verify_pass(password, hash)
        {:total_heap_size, words} = :erlang.process_info(self(), :total_heap_size)
        words
      end)
      |> Task.await()

    assert heap_words < 100_000
  end

  test "hash_pwd_salt legacy prefix" do
    assert String.starts_with?(Bcrypt.hash_pwd_salt(""), "$2b$")
    assert String.starts_with?(Bcrypt.hash_pwd_salt("", legacy: true), "$2a$")
    assert String.starts_with?(Bcrypt.hash_pwd_salt("", legacy: false), "$2b$")
  end
end
