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
    suite = c.collect tests_dir

    result = Test::Unit::UI::Console::TestRunner.run(suite)
    result.passed?
end

exit(main)
