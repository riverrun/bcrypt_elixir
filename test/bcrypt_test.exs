defmodule BcryptTest do
  use ExUnit.Case

  import BcryptTestHelper

  test "hashing and checking passwords" do
    wrong_list = ["aged2h$ru", "2dau$ehgr", "rg$deh2au", "2edrah$gu", "$agedhur2", ""]
    password_hash_check("hard2guess", wrong_list)
  end

  test "hashing and checking passwords with characters from the extended ascii set" do
    wrong_list = ["eáé åöêô ëaäo", "aäôáö eéoêë å", " aöêôée oåäëá", "åaêöéäëeoô á ", ""]
    password_hash_check("aáåä eéê ëoôö", wrong_list)
  end

  test "hashing and checking passwords with non-ascii characters" do
    wrong_list = [
      "и Скл;лекьоток к олсомзь",
      "кеокок  зС омлслтььлок;и",
      "е  о оиькльлтСо;осккклзм",
      ""
    ]

    password_hash_check("Сколько лет; сколько зим", wrong_list)
  end

  test "hashing and checking passwords with mixed characters" do
    wrong_list = ["Я☕t☔s❤ùo", "o❤ Я☔ùrtês☕", " ùt❤o☕☔srêЯ", "ù☕os êt❤☔rЯ", ""]
    password_hash_check("Я❤três☕ où☔", wrong_list)
  end

  test "check password using check_pass, which uses the user map as input" do
    wrong_list = ["บดสคสััีวร", "สดรบัีสัคว", "สวดัรคบัสี", "ดรสสีวคบัั", "วรคดสัสีับ", ""]
    check_pass_check("สวัสดีครับ", wrong_list)
  end

  test "add hash to map and set password to nil" do
    wrong_list = ["êäöéaoeôáåë", "åáoêëäéôeaö", "aäáeåëéöêôo", ""]
    add_hash_check("aáåäeéêëoôö", wrong_list)
  end

  test "hash_pwd_salt legacy prefix" do
    assert String.starts_with?(Bcrypt.hash_pwd_salt(""), "$2b$")
    assert String.starts_with?(Bcrypt.hash_pwd_salt("", legacy: true), "$2a$")
    assert String.starts_with?(Bcrypt.hash_pwd_salt("", legacy: false), "$2b$")
  end

  test "gen_salt number of rounds" do
    assert String.starts_with?(Bcrypt.gen_salt(), "$2b$12$")
    assert String.starts_with?(Bcrypt.gen_salt(8), "$2b$08$")
    assert String.starts_with?(Bcrypt.gen_salt(20), "$2b$20$")
  end

  test "gen_salt length of salt" do
    assert byte_size(Bcrypt.gen_salt(8)) == 29
    assert byte_size(Bcrypt.gen_salt(20)) == 29
  end

  test "wrong input to gen_salt" do
    assert String.starts_with?(Bcrypt.gen_salt(3), "$2b$04$")
    assert String.starts_with?(Bcrypt.gen_salt(32), "$2b$31$")
  end

  test "gen_salt with support for $2a$ prefix" do
    assert String.starts_with?(Bcrypt.gen_salt(8, true), "$2a$08$")
    assert String.starts_with?(Bcrypt.gen_salt(12, true), "$2a$12$")
  end

  test "add_hash and check_pass" do
    assert {:ok, user} = Bcrypt.add_hash("password") |> Bcrypt.check_pass("password")
    assert {:error, "invalid password"} =
             Bcrypt.add_hash("pass") |> Bcrypt.check_pass("password")
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
