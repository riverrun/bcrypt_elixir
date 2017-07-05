defmodule Bcrypt.StatsTest do
  use ExUnit.Case

  import ExUnit.CaptureIO
  alias Bcrypt.Stats

  test "print report with default options" do
    report = capture_io(fn -> Stats.report() end)
    assert report =~ "Hash: $2b$12$"
    assert report =~ "Log rounds: 12\n"
    assert report =~ "Verification ok"
  end

  test "use custom options" do
    report = capture_io(fn -> Stats.report(log_rounds: 10) end)
    assert report =~ "Hash: $2b$10$"
    assert report =~ "Log rounds: 10\n"
    assert report =~ "Verification ok"
  end

end
