require "pathname"

module OpenID
  module TestDataMixin
    TESTS_DIR = Pathname.new(__FILE__).dirname

    def read_data_file(filename, lines=true)
      fname = TESTS_DIR.join('data', filename).to_s

      if lines
        File.readlines(fname)
      else
        File.read(fname)
      end
    end
  end
end
