
TESTS_DIR = Pathname.new(__FILE__).dirname

def read_data_file(filename)
  File.readlines(TESTS_DIR.join('data', filename).to_s)
end
