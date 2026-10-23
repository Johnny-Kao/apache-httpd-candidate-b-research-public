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
  def initialize(bytes, declared)
    @bytes = bytes
    @declared = declared
  end

  def call(stream)
    # Thin supports callable streaming bodies. The application response is
    # already malformed because Rack::Files used character count for
    # Content-Length. Return control to Thin after the declared bytes and emit
    # only the naturally remaining bytes later on the event loop.
    stream << @bytes.byteslice(0, @declared)
    EventMachine.add_timer(0.25) do
      tail = @bytes.byteslice(@declared..)
      stream << tail if tail && !tail.empty?
      stream.close
    end
  end
end

class DelayedVictimBody
  def initialize(body)
    @body = body
  end

  def call(stream)
    EventMachine.add_timer(0.50) do
      stream << @body
      stream.close
    end
  end
end

files = Rack::Files.new(ENV.fetch("RACK_FILES_ROOT"))

app = lambda do |env|
  if env["PATH_INFO"] == "/victim"
    body = if ENV["RACK_THIN_IMPACT"] == "1"
      "<html><body>" + ("B" * 2048) + "VICTIM-OWN</body></html>"
    else
      "VICTIM-OWN"
    end
    [200, {"content-type" => ENV["RACK_THIN_IMPACT"] == "1" ? "text/html" : "text/plain",
           "content-length" => body.bytesize.to_s,
           "x-tenant" => "B"},
     ENV["RACK_THIN_FAST_VICTIM"] == "1" ? [body] : DelayedVictimBody.new(body)]
  else
    status, headers, body = files.call(env)
    if env["PATH_INFO"].start_with?("/missing/")
      bytes = +""
      body.each { |part| bytes << part }
      [status, headers, AsyncBody.new(bytes, headers.fetch("content-length").to_i)]
    else
      [status, headers, body]
    end
  end
end

run Utf8PathInfo.new(app)
