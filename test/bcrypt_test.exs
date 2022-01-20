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

  test "add_hash function" do
    password = Enum.random(ascii_passwords())
    assert add_hash_creates_map(Bcrypt, password)
  end

  test "check_pass function" do
    password = Enum.random(ascii_passwords())
    assert check_pass_returns_user(Bcrypt, password)
    assert check_pass_returns_error(Bcrypt, password)
    assert check_pass_nil_user(Bcrypt)
  end

  test "hash_pwd_salt legacy prefix" do
    assert String.starts_with?(Bcrypt.hash_pwd_salt(""), "$2b$")
    assert String.starts_with?(Bcrypt.hash_pwd_salt("", legacy: true), "$2a$")
    assert String.starts_with?(Bcrypt.hash_pwd_salt("", legacy: false), "$2b$")
  end

  test "add_hash and check_pass" do
    assert {:ok, user} = Bcrypt.add_hash("password") |> Bcrypt.check_pass("password")
    assert {:error, "invalid password"} = Bcrypt.add_hash("pass") |> Bcrypt.check_pass("password")
    assert Map.has_key?(user, :password_hash)
  end

  test "add_hash with a custom hash_key and check_pass" do
    assert {:ok, user} =
             Bcrypt.add_hash("password", hash_key: :encrypted_password)
             |> Bcrypt.check_pass("password")

    assert {:error, "invalid password"} =
             Bcrypt.add_hash("pass", hash_key: :encrypted_password)
             |> Bcrypt.check_pass("password")

    assert Map.has_key?(user, :encrypted_password)
  end

  test "check_pass with custom hash_key" do
    assert {:ok, user} =
             Bcrypt.add_hash("password", hash_key: :custom_hash)
             |> Bcrypt.check_pass("password", hash_key: :custom_hash)

    assert Map.has_key?(user, :custom_hash)
  end

  test "check_pass with invalid hash_key" do
    {:error, message} =
      Bcrypt.add_hash("password", hash_key: :unconventional_name)
      |> Bcrypt.check_pass("password")

    assert message =~ "no password hash found"
  end

  test "check_pass with password that is not a string" do
    assert {:error, message} = Bcrypt.add_hash("pass") |> Bcrypt.check_pass(nil)
    assert message =~ "password is not a string"
  end
end
