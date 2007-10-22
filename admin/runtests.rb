#!/usr/bin/ruby

require "logger"
require "stringio"
require "pathname"

require 'test/unit/collector/dir'
require 'test/unit/ui/console/testrunner'

def main
  tests_dir = Pathname.new(__FILE__).dirname.dirname.join('test')

  # Collect tests from everything named test_*.rb.
  c = Test::Unit::Collector::Dir.new
  c.base = tests_dir
  suite = c.collect

    result = Test::Unit::UI::Console::TestRunner.run(suite)
    result.passed?
end

exit(main)
