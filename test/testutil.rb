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
end
