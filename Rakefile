#!/usr/bin/env rake
require 'bundler/gem_tasks'

require 'rake/testtask'

desc "Run tests"
Rake::TestTask.new('test') do |t|
  t.libs << 'lib'
  t.libs << 'test'
  t.test_files = FileList["test/**/test_*.rb"]
  t.verbose = false
end

task :default => :test
