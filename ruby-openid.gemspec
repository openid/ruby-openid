# -*- encoding: utf-8 -*-
$:.push File.expand_path("../lib", __FILE__)
require "openid/version"

Gem::Specification.new do |s|
  s.name        = "ruby-openid"
  s.version     = OpenID::VERSION
  s.authors     = ["JanRain, Inc", "Mike Mell"]
  s.email       = ["openid@janrain.com", "mike.mell@nthwave.net"]
  s.homepage    = 'https://github.com/mmell/ruby-openid'
  s.summary     = 'A library for consuming and serving OpenID identities.'
  s.description = s.summary

  s.rubyforge_project = "ruby-openid"

  s.files         = `git ls-files`.split("\n")
  s.test_files    = `git ls-files -- {test,spec,features}/*`.split("\n")
  s.executables   = `git ls-files -- bin/*`.split("\n").map{ |f| File.basename(f) }
  s.require_paths = ["lib"]

  # specify any dependencies here; for example:
  # s.add_development_dependency "rspec"
  # s.add_runtime_dependency "rest-client"
end
