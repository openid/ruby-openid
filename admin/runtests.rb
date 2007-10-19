#!/usr/bin/ruby

require "logger"
require "stringio"
require "pathname"

require 'test/unit'
require 'test/unit/collector/dir'

tests_dir = Pathname.new(__FILE__).dirname.dirname.join('test')

# Collect tests from everything named test_*.rb.
c = Test::Unit::Collector::Dir.new
suite = c.collect tests_dir

require 'test/unit/ui/console/testrunner'
Test::Unit::UI::Console::TestRunner.run(suite)
