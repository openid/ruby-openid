# Utilities that are only used in the testing code
require 'stringio'

module OpenID
  module TestUtil
    def assert_log_matches(regex)
      old_logger = Util.logger
      log_output = StringIO.new
      Util.logger = Logger.new(log_output)
      yield
      assert_match(regex, log_output.string)
    ensure
      Util.logger = old_logger
    end
  end
end

