defmodule BcryptTest do
  use ExUnit.Case

  def hash_check_password(password, wrong1, wrong2, wrong3) do
    hash = Bcrypt.hash_pwd_salt(password)
    assert Bcrypt.verify_pass(password, hash) == true
    assert Bcrypt.verify_pass(wrong1, hash) == false
    assert Bcrypt.verify_pass(wrong2, hash) == false
    assert Bcrypt.verify_pass(wrong3, hash) == false
  end

  test "hashing and checking passwords" do
    hash_check_password("password", "passwor", "passwords", "pasword")
    hash_check_password("hard2guess", "ha rd2guess", "had2guess", "hardtoguess")
  end

  test "hashing and checking passwords with characters from the extended ascii set" do
    hash_check_password("aáåäeéêëoôö", "aáåäeéêëoö", "aáåeéêëoôö", "aáå äeéêëoôö")
    hash_check_password("aáåä eéêëoôö", "aáåä eéê ëoö", "a áåeé êëoôö", "aáå äeéêëoôö")
  end

  test "hashing and checking passwords with non-ascii characters" do
    hash_check_password(
      "Сколько лет, сколько зим",
      "Сколько лет,сколько зим",
      "Сколько лет сколько зим",
      "Сколько лет, сколько"
    )

    hash_check_password("สวัสดีครับ", "สวัดีครับ", "สวัสสดีครับ", "วัสดีครับ")
  end

  test "hashing and checking passwords with mixed characters" do
    hash_check_password("Я❤três☕ où☔", "Я❤tres☕ où☔", "Я❤três☕où☔", "Я❤três où☔")
  end

  test "hash_pwd_salt number of rounds" do
    assert String.starts_with?(Bcrypt.hash_pwd_salt("", log_rounds: 4), "$2b$04$")
    Application.put_env(:bcrypt_elixir, :log_rounds, 4)
    assert String.starts_with?(Bcrypt.hash_pwd_salt(""), "$2b$04$")
    Application.delete_env(:bcrypt_elixir, :log_rounds)
    assert String.starts_with?(Bcrypt.hash_pwd_salt(""), "$2b$12$")
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
end
