# Changelog

## 2.3.0

* Deprecated Ruby 1.8 support - 0694bebc83de0313cfef73a5d0ffd9a293ae71a0
* Fixed encoding errors in test suite - 7ac8e3978f9c733bd5ee8d6b742b515b5427ded2
* Be aware when using Hash or Array as default value for unknown Hash keys - #58
* Stop overwriting String#starts_with? and String#ends_with? if defined - #55
* Ignore Associations For OpenID2 (Google's Security Bug Fix) - #53
* Change "oauth" to "ui" in variable name in the UI extension - #52
* Eliminating runtime warnings - #50 #56
* Upgrade example Rails provider/consumer app to Rails 3 - #49

## 2.2.3

* Fixed 'invalid byte sequence in UTF-8' error in parse_link_attrs - 0f46921a97677b83b106366c805063105c5e9f20
* Fixed license information in gemspec - f032e949e1ca9078ab7508d9629398ca2c36980a
* Update starts/ends_with? to handle nil prefix - beee5e8d1dc24ad55725cfcc720eefba6bdbd279

## 2.2.2

* Limit fetching file size & disable XML entity expansion - be2bab5c21f04735045e071411b349afb790078f

  Avoid DoS attack to RPs using large XRDS / too many XML entity expansion in XRDS.

## 2.2.1

* Make bundle exec rake work - 2100f281172427d1557ebe76afbd24072a22d04f
* State license in gemspec for automated tools / rubygems.org page - 2d5c3cd8f2476b28d60609822120c79d71919b7b
* Use default-external encoding instead of ascii for badly encoded pages - a68d2591ac350459c874da10108e6ff5a8c08750
* Colorize output and reveal tests that never ran - 4b0143f0a3b10060d5f52346954219bba3375039

## 2.2.0

* Bundler compatibility and bundler gem tasks - 72d551945f9577bf5d0e516c673c648791b0e795
* register_namespace_alias for AX message - aeaf050d21aeb681a220758f1cc61b9086f73152
* Fixed JRuby (1.9 mode) incompatibilty - 40baed6cf7326025058a131c2b76047345618539
* Added UI extension support - a276a63d68639e985c1f327cf817489ccc5f9a17
* Add attr_reader for setup_url on SetupNeededResponse - 75a7e98005542ede6db3fc7f1fc551e0a2ca044a
* Encode form inputs - c9e9b5b52f8a23df3159c2387b6330d5df40f35b
* Fixed cleanup AR associations whose expiry is past, not upcoming - 2265179a6d5c8b51ccc741180db46b618dd3caf9
* Fixed issue with Memcache store and Dalli - ef84bf73da9c99c67b0632252bf0349e2360cbc7
* Improvements to ActiveRecordStore's gc rake task - 847e19bf60a6b8163c1e0d2e96dbd805c64e2880
