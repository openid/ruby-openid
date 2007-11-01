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
    attr_reader :status, :body

    def initialize(status, body)
      @status = status
      @body = body
    end
  end
end
