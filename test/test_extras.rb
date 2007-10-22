require 'test/unit'
require 'openid/extras'

class StartsWithTestCase < Test::Unit::TestCase
    def test_starts_with
        [["anything", ""],
         ["something else", ""],
         ["", ""],
         ["foos", "foo"],
        ].each{|str,target| assert(str.starts_with?(target))}
    end

    def test_not_starts_with
        [["x", "y"],
         ["foos", "ball"],
         ["xx", "xy"],
        ].each{|str,target| assert(!(str.starts_with? target)) }
    end
end
