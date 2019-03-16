# Ruby OpenID Library Installation

## Install as a gem

`ruby-openid` is distributed on [RubyGems](https://rubygems.org/).
Install it:

    gem install ruby-openid

This is probably what you need.

## Manual Installation

Unpack the archive and run `setup.rb` to install:

    ruby setup.rb

`setup.rb` installs the library into your system ruby. If don't want to
add openid to you system ruby, you may instead add the `lib` directory of
the extracted tarball to your `RUBYLIB` environment variable:

    $ export RUBYLIB=${RUBYLIB}:/path/to/ruby-openid/lib

## Testing the Installation

Make sure everything installed ok:

    $> irb
    irb$> require "openid"
    => true

## Run the test suite

Go into the test directory and execute the `runtests.rb` script.

## Next steps

* Run `consumer.rb` in the `examples/` directory.
* Get started writing your own consumer using `OpenID::Consumer`
* Write your own server with `OpenID::Server`
* Use the `OpenIDLoginGenerator`! Read `examples/README.md` for more info.
