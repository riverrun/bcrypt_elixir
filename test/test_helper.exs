ExUnit.start()

defmodule BcryptTestHelper do
  use ExUnit.Case

  def password_hash_check(password, wrong_list) do
    hash = Bcrypt.hash_pwd_salt(password)
    assert Bcrypt.verify_pass(password, hash)

    for wrong <- wrong_list do
      refute Bcrypt.verify_pass(wrong, hash)
    end
  end

  def add_hash_check(password, wrong_list) do
    %{password_hash: hash, password: nil} = Bcrypt.add_hash(password)
    assert Bcrypt.verify_pass(password, hash)

    for wrong <- wrong_list do
      refute Bcrypt.verify_pass(wrong, hash)
    end
  end

  def check_pass_check(password, wrong_list) do
    hash = Bcrypt.hash_pwd_salt(password)
    user = %{id: 2, name: "fred", password_hash: hash}
    assert Bcrypt.check_pass(user, password) == {:ok, user}
    assert Bcrypt.check_pass(nil, password) == {:error, "invalid user-identifier"}

    for wrong <- wrong_list do
      assert Bcrypt.check_pass(user, wrong) == {:error, "invalid password"}
    end
  end
end
