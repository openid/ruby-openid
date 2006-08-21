require 'rubygems'

SPEC = Gem::Specification.new do |s|
  s.name = `cat admin/library-name`.strip
  s.version = `darcs changes --tags= | awk '$1 == "tagged" { print $2 }' | head -n 1`.strip
  s.author = 'Brian Ellin (JanRain, Inc)'
  s.email = 'brian@janrian.com'
  s.homepage = 'http://www.openidenabled.com/openid/libraries/ruby'
  s.platform = Gem::Platform::RUBY
  s.summary = 'A library for consuming and serving OpenID identities.'
  files = Dir.glob("{examples,lib,test}/**/*")
  s.files = files.delete_if {|f| f.include?('_darcs') || f.include?('admin')}
  s.require_path = 'lib'
  s.autorequire = 'openid'
  s.test_file = 'test/runtests.rb'
  s.has_rdoc = true
  s.extra_rdoc_files = ['README','INSTALL','COPYING','TODO']
  s.rdoc_options << '--main' << 'README'
  s.add_dependency('ruby-yadis', '>= 0.3.3')
end
