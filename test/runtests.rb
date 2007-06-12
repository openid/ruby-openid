#!/usr/bin/ruby

require "openid/util"
require "logger"
require "stringio"

# Redirect logging output to a buffer.
logfile = StringIO.new
OpenID::Util.setLogger(Logger.new(logfile))

require 'test/unit'
require 'test/unit/collector/dir'

# Collect tests from everything named test_*.rb.
c = Test::Unit::Collector::Dir.new
suite = c.collect

require 'test/unit/ui/console/testrunner'
Test::Unit::UI::Console::TestRunner.run(suite)

# Dump the logs.
#logfile.rewind
#puts logfile.read
