defmodule Bcrypt.StatsTest do
  use ExUnit.Case

  import ExUnit.CaptureIO
  alias Bcrypt.Stats

  test "print report with default options" do
    report = capture_io(fn -> Stats.report() end)
    assert report =~ "Hash:\t\t$2b$12$"
    assert report =~ "Log rounds:\t12\n"
    assert report =~ "Verification OK"
  end

  test "use custom options" do
    report = capture_io(fn -> Stats.report(log_rounds: 10) end)
    assert report =~ "Hash:\t\t$2b$10$"
    assert report =~ "Log rounds:\t10\n"
    assert report =~ "Verification OK"
  end

end
