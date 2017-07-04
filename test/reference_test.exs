defmodule Bcrypt.ReferenceTest do
  use ExUnit.Case

  alias Bcrypt.Base

  def read_file(filename, digest) do
    tests = Path.expand("support/#{filename}", __DIR__)
            |> File.read!
            |> String.split("\n", trim: true)
    for t <- tests do
      [password, salt, iterations, dklen, hash] = String.split(t, ",", trim: true)
      rounds = String.to_integer(iterations)
      length = String.to_integer(dklen)
      assert Base.hash_password(password, salt, rounds: rounds, digest: digest,
                                length: length, format: :hex) == hash
    end
  end


end
