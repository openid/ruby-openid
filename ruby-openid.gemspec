# -*- encoding: utf-8 -*-
require File.expand_path('../lib/openid/version', __FILE__)

Gem::Specification.new do |s|
  s.name = 'ruby-openid'
  s.author = 'JanRain, Inc'
  s.email = 'openid@janrain.com'
  s.homepage = 'https://github.com/openid/ruby-openid'
  s.summary = 'A library for consuming and serving OpenID identities.'
  s.version = OpenID::VERSION
  s.licenses = ["Ruby", "Apache Software License 2.0"]

  # Files
  files = Dir.glob("{examples,lib,test}/**/*")
  files << 'NOTICE' << 'CHANGELOG.md'
  s.files = files.delete_if {|f| f.include?('_darcs') || f.include?('admin')}
  s.require_paths = ['lib']
  s.autorequire = 'openid'
  s.executables = s.files.grep(%r{^bin/}).map{ |f| File.basename(f) }
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # RDoc
  s.has_rdoc = true
  s.extra_rdoc_files = ['README.md', 'INSTALL.md', 'LICENSE', 'UPGRADE.md']
  s.rdoc_options << '--main' << 'README.md'

  s.add_development_dependency 'minitest', '>= 5'
end
