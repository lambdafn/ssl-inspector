defmodule SslInspectorTest do
  use ExUnit.Case

  @non_exisitent_host "nonsuch.sslreminder.io"

  doctest SslInspector

  test "get_cert_expiry_date" do
    expiry_date = SslInspector.get_cert_expiry_date("www.google.co.uk", 443)

    assert expiry_date == {:ok, ~D[2017-10-04]}
  end

  test "get_cert_expiry_date for host that doesn't resolve" do
    expiry_date = SslInspector.get_cert_expiry_date(@non_exisitent_host, 443)

    assert expiry_date == {:error, :nxdomain}
  end

  test "get_cert_expiry_date plain HTTP server" do
    expiry_date = SslInspector.get_cert_expiry_date("www.google.co.uk", 80)

    assert expiry_date == {:error, :no_ssl}
  end
end
