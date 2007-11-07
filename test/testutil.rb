require "pathname"

module OpenID
  module TestDataMixin
    TESTS_DIR = Pathname.new(__FILE__).dirname
    TEST_DATA_DIR = Pathname.new('data')

    def read_data_file(filename, lines=true, data_dir=TEST_DATA_DIR)
      fname = TESTS_DIR.join(data_dir, filename)

      if lines
        fname.readlines
      else
        fname.read
      end
    end
  end

  module FetcherMixin
    def with_fetcher(fetcher)
      original_fetcher = OpenID.fetcher
      begin
        OpenID.fetcher = fetcher
        return yield
      ensure
        OpenID.fetcher = original_fetcher
      end
    end
  end

  module Const
    def const(symbol, value)
      (class << self;self;end).instance_eval do
        define_method(symbol) { value }
      end
    end
  end

  class MockResponse
    attr_reader :code, :body

    def initialize(code, body)
      @code = code.to_s
      @body = body
    end
  end

  module ProtocolErrorMixin
    def assert_protocol_error(str_prefix)
      begin
        result = yield
      rescue ProtocolError => why
        message = "Expected prefix #{str_prefix.inspect}, got "\
                  "#{why.message.inspect}"
        assert(why.message.starts_with?(str_prefix), message)
      else
        fail("Expected ProtocolError. Got #{result.inspect}")
      end
    end
  end

  module OverrideMethodMixin
    def with_method_overridden(method_name, proc)
      original = method(method_name)
      begin
        define_method(method_name, proc)
        module_function(method_name)
        yield
      ensure
        define_method(method_name, original)
        module_function(method_name)
      end
    end
  end

  # To use:
  # > x = Object.new
  # > x.extend(InstanceDefExtension)
  # > x.instance_def(:monkeys) do
  # >   "bananas"
  # > end
  # > x.monkeys
  #
  module InstanceDefExtension
    def instance_def(method_name, &proc)
      (class << self;self;end).instance_eval do
        define_method(method_name, proc)
      end
    end
  end

end
