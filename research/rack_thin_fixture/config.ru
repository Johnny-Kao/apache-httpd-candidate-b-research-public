# frozen_string_literal: true

gem "rack", "= 3.2.5"
require "rack"

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

class DelayedBody
  def initialize(bytes, declared)
    @bytes = bytes
    @declared = declared
  end

  def each
    # The application response is already malformed because Rack::Files used
    # character count for Content-Length. Split a normal streaming body at the
    # declared boundary and delay only the naturally remaining bytes.
    yield @bytes.byteslice(0, @declared)
    sleep 0.25
    tail = @bytes.byteslice(@declared..)
    yield tail if tail && !tail.empty?
  end
end

files = Rack::Files.new(ENV.fetch("RACK_FILES_ROOT"))

app = lambda do |env|
  if env["PATH_INFO"] == "/victim"
    body = "VICTIM-OWN"
    [200, {"content-type" => "text/plain",
           "content-length" => body.bytesize.to_s,
           "x-tenant" => "B"}, [body]]
  else
    status, headers, body = files.call(env)
    if env["PATH_INFO"].start_with?("/missing/")
      bytes = +""
      body.each { |part| bytes << part }
      [status, headers, DelayedBody.new(bytes, headers.fetch("content-length").to_i)]
    else
      [status, headers, body]
    end
  end
end

run Utf8PathInfo.new(app)
