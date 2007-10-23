# Utilities that are only used in the testing code
require 'stringio'

module OpenID
  module TestUtil
    def assert_log_matches(*regexes)
      begin
        old_logger = Util.logger
        log_output = StringIO.new
        Util.logger = Logger.new(log_output)
        yield
      ensure
        Util.logger = old_logger
      end
      log_output.rewind
      log_lines = log_output.readlines
      assert_equal(regexes.length, log_lines.length)
      log_output.readlines.zip(regexes) do |line, regex|
        assert_match(regex, line)
      end
    end
  end
end

