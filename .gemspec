require 'rubygems'

SPEC = Gem::Specification.new do |s|
  s.name = `cat admin/library-name`.strip
  s.version = '2.1.8'
  s.author = 'JanRain, Inc, Mike Mell'
  s.email = 'mike.mell@nthwave.net'
  s.homepage = 'https://github.com/mmell/ruby-openid'
  s.platform = Gem::Platform::RUBY
  s.summary = 'A library for consuming and serving OpenID identities.'
  files = Dir.glob("{examples,lib,test}/**/*")
  files << 'NOTICE' << 'CHANGELOG'
  s.files = files.delete_if {|f| f.include?('_darcs') || f.include?('admin')}
  s.require_path = 'lib'
  s.autorequire = 'openid'
  s.test_file = 'admin/runtests.rb'
  s.has_rdoc = true
  s.extra_rdoc_files = ['README','INSTALL','LICENSE','UPGRADE']
  s.rdoc_options << '--main' << 'README'
end
