# frozen_string_literal: true

# Rack 3.2 standard response-body contract: an Enumerable body may stream by
# yielding chunks from #each. This fixture uses String#each_line for the
# natural victim case; it has no timer, sleep, hijack, second response, or
# manipulated Content-Length.
gem "rack", "= 3.2.5"
require "rack"
require "eventmachine"

class Utf8PathInfo
  def initialize(app)
    @app = app
  end

  def call(env)
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
    victim_mode = ENV.fetch("RACK_THIN_VICTIM_MODE", "plain")
    body = if victim_mode == "enumerable_stream"
      # A large synthetic download/report body. String#each_line is the
      # standard Enumerable Rack body path and yields without any timer.
      "B_STREAM_CHUNK_0000\n" * 16_384
    else
      "VICTIM-OWN"
    end
    headers = {
      "content-type" => "text/plain",
      "content-length" => body.bytesize.to_s,
      "x-tenant" => "B",
      "x-probe-id" => env["HTTP_X_PROBE_ID"].to_s,
      "x-backend-peer" => env["REMOTE_PORT"].to_s
    }
    response_body = if victim_mode == "enumerable_stream"
      body.each_line
    elsif ENV["RACK_THIN_FAST_VICTIM"] == "1"
      [body]
    else
      DelayedVictimBody.new(body, Float(ENV.fetch("RACK_THIN_B_DELAY", "0.50")))
    end
    [200, headers, response_body]
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
      mode = ENV.fetch("RACK_THIN_A_MODE", "async_malformed")
      headers["content-length"] = bytes.bytesize.to_s if mode == "correct_length"
      delay = Float(ENV.fetch("RACK_THIN_A_DELAY", "0.25"))
      if mode == "buffered_malformed" || mode == "correct_length_buffered"
        [status, headers, [bytes]]
      else
        [status, headers, AsyncBody.new(bytes, headers.fetch("content-length").to_i, delay)]
      end
    else
      [status, headers, body]
    end
  end
end

run Utf8PathInfo.new(app)
