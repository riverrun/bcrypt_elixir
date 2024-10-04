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

  test "hash_pwd_salt legacy prefix" do
    assert String.starts_with?(Bcrypt.hash_pwd_salt(""), "$2b$")
    assert String.starts_with?(Bcrypt.hash_pwd_salt("", legacy: true), "$2a$")
    assert String.starts_with?(Bcrypt.hash_pwd_salt("", legacy: false), "$2b$")
  end
end
