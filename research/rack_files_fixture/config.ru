# frozen_string_literal: true

require "rack"

files = Rack::Files.new(ENV.fetch("RACK_FILES_ROOT"))

run lambda { |env|
  if env["PATH_INFO"] == "/victim"
    body = "VICTIM-OWN"
    [200, {
      "content-type" => "text/plain",
      "content-length" => body.bytesize.to_s,
      "x-tenant" => "B"
    }, [body]]
  else
    # Tenant A controls only the requested path. Rack::Files generates the
    # response, including its own error framing.
    files.call(env)
  end
}
