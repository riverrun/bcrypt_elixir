defmodule Bcrypt.BaseTest do
  use ExUnit.Case

  alias Bcrypt.Base

  def check_vectors(data) do
    for {password, salt, stored_hash} <- data do
      assert Base.hash_password(password, salt) == stored_hash
    end
  end

  test "Openwall Bcrypt tests" do
    [
      {"U*U",
        "$2a$05$CCCCCCCCCCCCCCCCCCCCC.",
        "$2a$05$CCCCCCCCCCCCCCCCCCCCC.E5YPO9kmyuRGyh0XouQYb4YMJKvyOeW"},
      {"U*U*",
        "$2a$05$CCCCCCCCCCCCCCCCCCCCC.",
        "$2a$05$CCCCCCCCCCCCCCCCCCCCC.VGOzA784oUp/Z0DY336zx7pLYAy0lwK"},
      {"U*U*U",
        "$2a$05$XXXXXXXXXXXXXXXXXXXXXO",
        "$2a$05$XXXXXXXXXXXXXXXXXXXXXOAcXxm9kjPGEMsLznoKqmqw7tc8WCx4a"},
      {"",
        "$2a$05$CCCCCCCCCCCCCCCCCCCCC.",
        "$2a$05$CCCCCCCCCCCCCCCCCCCCC.7uG0VCzI2bS7j6ymqJi9CdcdxiRTWNy"},
      {"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789",
        "$2a$05$abcdefghijklmnopqrstuu",
        "$2a$05$abcdefghijklmnopqrstuu5s2v8.iXieOjg/.AySBTTZIIVFJeBui"}
    ] |> check_vectors
  end

  test "OpenBSD Bcrypt tests" do
    [
      {<<0xa3>>,
        "$2b$05$/OK.fbVrR/bpIqNJ5ianF.",
        "$2b$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq"},
      {<<0xa3>>,
        "$2a$05$/OK.fbVrR/bpIqNJ5ianF.",
        "$2a$05$/OK.fbVrR/bpIqNJ5ianF.Sa7shbm4.OzKpvFnX1pQLmQW96oUlCq"},
      {<<0xff, 0xff, 0xa3>>,
        "$2b$05$/OK.fbVrR/bpIqNJ5ianF.",
        "$2b$05$/OK.fbVrR/bpIqNJ5ianF.CE5elHaaO4EbggVDjb8P19RukzXSM3e"},
      {"000000000000000000000000000000000000000000000000000000000000000000000000",
        "$2a$05$CCCCCCCCCCCCCCCCCCCCC.",
        "$2a$05$CCCCCCCCCCCCCCCCCCCCC.6.O1dLNbjod2uo0DVcW.jHucKbPDdHS"},
      {"000000000000000000000000000000000000000000000000000000000000000000000000",
        "$2b$05$CCCCCCCCCCCCCCCCCCCCC.",
        "$2b$05$CCCCCCCCCCCCCCCCCCCCC.6.O1dLNbjod2uo0DVcW.jHucKbPDdHS"}
    ] |> check_vectors
  end

  test "Long password $2b$ prefix tests" do
    [
      {"01234567890123456789012345678901234567890123456789012345678901234567890123456789" <>
        "0123456789012345678901234567890123456789012345678901234567890123456789012345678" <>
          "901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234",
        "$2b$05$CCCCCCCCCCCCCCCCCCCCC.",
        "$2b$05$CCCCCCCCCCCCCCCCCCCCC.XxrQqgBi/5Sxuq9soXzDtjIZ7w5pMfK"},
      {"01234567890123456789012345678901234567890123456789012345678901234567890123456789" <>
        "0123456789012345678901234567890123456789012345678901234567890123456789012345678" <>
          "9012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345",
        "$2b$05$CCCCCCCCCCCCCCCCCCCCC.",
        "$2b$05$CCCCCCCCCCCCCCCCCCCCC.XxrQqgBi/5Sxuq9soXzDtjIZ7w5pMfK"}
    ] |> check_vectors
  end

  test "Long password old $2a$ prefix tests" do
    [
      {"01234567890123456789012345678901234567890123456789012345678901234567890123456789" <>
        "0123456789012345678901234567890123456789012345678901234567890123456789012345678" <>
          "901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234",
        "$2a$05$CCCCCCCCCCCCCCCCCCCCC.",
        "$2a$05$CCCCCCCCCCCCCCCCCCCCC.6.O1dLNbjod2uo0DVcW.jHucKbPDdHS"},
      {"01234567890123456789012345678901234567890123456789012345678901234567890123456789" <>
        "0123456789012345678901234567890123456789012345678901234567890123456789012345678" <>
          "9012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345",
        "$2a$05$CCCCCCCCCCCCCCCCCCCCC.",
        "$2a$05$CCCCCCCCCCCCCCCCCCCCC.6.O1dLNbjod2uo0DVcW.jHucKbPDdHS"}
    ] |> check_vectors
  end

  test "known non-ascii characters tests" do
    [
      {"ππππππππ",
        "$2a$10$.TtQJ4Jr6isd4Hp.mVfZeu",
        "$2a$10$.TtQJ4Jr6isd4Hp.mVfZeuh6Gws4rOQ/vdBczhDx.19NFK0Y84Dle"}
    ] |> check_vectors
  end

  test "Consistency tests" do
    [
      {"p@5sw0rd",
        "$2b$12$zQ4CooEXdGqcwi0PHsgc8e",
        "$2b$12$zQ4CooEXdGqcwi0PHsgc8eAf0DLXE/XHoBE8kCSGQ97rXwuClaPam"},
      {"C'est bon, la vie!",
        "$2b$12$cbo7LZ.wxgW4yxAA5Vqlv.",
        "$2b$12$cbo7LZ.wxgW4yxAA5Vqlv.KR6QFPt4qCdc9RYJNXxa/rbUOp.1sw."},
      {"ἓν οἶδα ὅτι οὐδὲν οἶδα",
        "$2b$12$LeHKWR2bmrazi/6P22Jpau",
        "$2b$12$LeHKWR2bmrazi/6P22JpauX5my/eKwwKpWqL7L5iEByBnxNc76FRW"}
    ] |> check_vectors
  end

  test "raise error if salt has unsupported prefix" do
    assert_raise ArgumentError, "Bcrypt does not support the 2x prefix", fn ->
      Base.hash_password("U*U", "$2x$05$CCCCCCCCCCCCCCCCCCCCC.")
    end
    assert_raise ArgumentError, "Bcrypt does not support the 2y prefix", fn ->
      Base.hash_password("U*U", "$2y$05$CCCCCCCCCCCCCCCCCCCCC.")
    end
  end

end
