defmodule SslInspector do
  @moduledoc """
  Easily inspect and retrieve information about an SSL server.
  """

  require Logger

  @doc """
  Get the expiry date of the server's SSL certificate.

  ## Examples

      iex> SslInspector.get_cert_expiry_date("www.google.co.uk", 443)
      {:ok, DateTime.from_naive!(~N[2017-10-04 11:56:00], "Etc/UTC")}

      iex> SslInspector.get_cert_expiry_date("nonsuch.sslreminder.io")
      {:error, :nxdomain}
  """
  def get_cert_expiry_date(host, port \\ 443) do
    case fetch_cert(host, port) do
      {:ok, cert} ->
        {:Certificate,
          {:TBSCertificate, :v3, _,
            _,
            _,
            {:Validity, {:utcTime, _}, {:utcTime, valid_to}},
            _,
            _, _, _,
            _
          },
          _,
          _
        } = :public_key.pkix_decode_cert(cert, :plain)

        {:ok, parse_cert_date(valid_to)}
      {:error, _} = e -> e
    end
  rescue
    e in MatchError ->
      Logger.error """
      Got a bad match in get_validity_dates (most likely a difference in certificate
      structure.)  Good luck!

      #{inspect e}

      Host: #{host}:#{port}
      """
      {:error, :badmatch}
  end

  defp fetch_cert(host, port) when is_binary(host) do
    fetch_cert(to_charlist(host), port)
  end
  defp fetch_cert(host, port) when is_list(host) do
    case :ssl.connect(host, port, [], 5_000) do
      {:ok,    sock}              -> {:ok, _cert} = :ssl.peercert(sock)
      {:error, :nxdomain}     = e -> e
      {:error, :econnrefused} = e -> e
      {:error, :closed}       = e -> e
      {:error, :timeout}      = e -> e
      {:error, {:tls_alert, 'record overflow'}} ->
        # Most likely caused by trying to connect to a plain HTTP server
        # with no SSL support
        {:error, :no_ssl}
    end
  end

  defp parse_cert_date(date) when is_list(date) do
    [year, month, day, hours, minutes, seconds] =
      date
      |> Enum.chunk(2)
      |> Enum.take(6)
      |> Enum.map(&List.to_integer/1)

    year = year + 2000
    Timex.to_datetime({{year, month, day}, {hours, minutes, seconds}})
  end
end
