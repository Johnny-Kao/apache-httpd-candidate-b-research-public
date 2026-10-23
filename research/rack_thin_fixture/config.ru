# frozen_string_literal: true

gem "rack", "= 3.2.5"
require "rack"
require "eventmachine"

class Utf8PathInfo
  def initialize(app)
    @app = app
  end

  def call(env)
    # Thin exposes the parsed path as an ASCII-8BIT string. A Rack adapter may
    # legitimately normalize PATH_INFO to UTF-8 before invoking the app.
    if env["PATH_INFO"]
      env["PATH_INFO"] = env["PATH_INFO"].dup.force_encoding(Encoding::UTF_8)
    end
    @app.call(env)
  end
end

class AsyncBody
  def initialize(bytes, declared, delay)
    @bytes = bytes
    @declared = declared
    @delay = delay
  end

  def call(stream)
    # Thin supports callable streaming bodies. The application response is
    # already malformed because Rack::Files used character count for
    # Content-Length. Return control to Thin after the declared bytes and emit
    # only the naturally remaining bytes later on the event loop.
    stream << @bytes.byteslice(0, @declared)
    EventMachine.add_timer(@delay) do
      tail = @bytes.byteslice(@declared..)
      stream << tail if tail && !tail.empty?
      stream.close
    end
  end
end

class DelayedVictimBody
  def initialize(body, delay)
    @body = body
    @delay = delay
  end

  def call(stream)
    EventMachine.add_timer(@delay) do
      stream << @body
      stream.close
    end
  end
end

files = Rack::Files.new(ENV.fetch("RACK_FILES_ROOT"))

def probe_log(env, tenant)
  path = ENV["RACK_THIN_REQUEST_LOG"]
  return unless path

  rid = env["HTTP_X_PROBE_ID"] || "-"
  peer = env["REMOTE_PORT"] || "-"
  path_info = env["PATH_INFO"] || "-"
  File.open(path, "a") do |log|
    log.puts("rid=#{rid} tenant=#{tenant} peer=#{peer} path=#{path_info}")
  end
end

app = lambda do |env|
  if env["PATH_INFO"] == "/victim"
    probe_log(env, "B")
    body = if ENV["RACK_THIN_IMPACT"] == "1"
      # A normal small HTML page is enough to test whether attacker bytes can
      # enter a victim document; keeping it short also makes the delayed A
      # tail large enough to cover the complete victim body.
      "<html><body>" + ("B" * 64) + "VICTIM-OWN</body></html>"
    else
      "VICTIM-OWN"
    end
    [200, {"content-type" => ENV["RACK_THIN_IMPACT"] == "1" ? "text/html" : "text/plain",
           "content-length" => body.bytesize.to_s,
           "x-tenant" => "B",
           "x-probe-id" => env["HTTP_X_PROBE_ID"].to_s,
           "x-backend-peer" => env["REMOTE_PORT"].to_s},
     ENV["RACK_THIN_FAST_VICTIM"] == "1" ? [body] :
      DelayedVictimBody.new(body, Float(ENV.fetch("RACK_THIN_B_DELAY", "0.50")))]
  else
    probe_log(env, "A")
    status, headers, body = files.call(env)
    headers["x-probe-id"] = env["HTTP_X_PROBE_ID"].to_s
    headers["x-backend-peer"] = env["REMOTE_PORT"].to_s
    headers["x-tenant"] = "A"
    headers.delete("x-cascade") if ENV["RACK_THIN_STRIP_CASCADE"] == "1"
    if env["PATH_INFO"].start_with?("/missing/")
      bytes = +""
      body.each { |part| bytes << part }
      delay = Float(ENV.fetch("RACK_THIN_A_DELAY", "0.25"))
      [status, headers, AsyncBody.new(bytes, headers.fetch("content-length").to_i, delay)]
    else
      [status, headers, body]
    end
  end
end

run Utf8PathInfo.new(app)
