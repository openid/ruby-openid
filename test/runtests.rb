#!/usr/bin/ruby

# the tests exploit some corner cases which generate warning messages
# on stderr.  try and silence those messages to avoid unnecessarily concerning
# the library user.
begin
  STDERR.reopen('/dev/null', 'w')
rescue
  puts "\nPlease ignore the non Test::Unit error messages generated below.\n"
end

require "teststore"
require "assoc"
require "dh"
require "util"
require "linkparse"
require "trustroot"
require "assoc"
require "server2"
require "consumer"
require "service"
require "urinorm"
