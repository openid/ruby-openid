require 'test/unit'
require 'openid/dh'

module OpenID
  class DiffieHellmanExposed < OpenID::DiffieHellman
    def DiffieHellmanExposed.strxor_for_testing(a, b)
      return DiffieHellmanExposed.strxor(a, b)
    end
  end

  class DiffieHellmanTestCase < Test::Unit::TestCase
    NUL = "\x00"

    def test_strxor_success
      [#input 1   input 2   expected
       [NUL,      NUL,      NUL     ],
       ["\x01",   NUL,      "\x01"  ],
       ["a",      "a",      NUL     ],
       ["a",      NUL,      "a"     ],
       ["abc",    NUL * 3,  "abc"   ],
       ["x" * 10, NUL * 10, "x" * 10],
       ["\x01",   "\x02",   "\x03"  ],
       ["\xf0",   "\x0f",   "\xff"  ],
       ["\xff",   "\x0f",   "\xf0"  ],
      ].each do |input1, input2, expected|
        actual = DiffieHellmanExposed.strxor_for_testing(input1, input2)
        assert_equal(expected, actual)
      end
    end

    def test_strxor_failure
      [
       ['',      'a'    ],
       ['foo',   'ba'   ],
       [NUL * 3, NUL * 4],
       [255,     127    ].map{|h| (0..h).map{|i|i.chr}.join('')},
      ].each do |aa, bb|
        assert_raises(ArgumentError) {
          DiffieHellmanExposed.strxor(aa, bb)
        }
      end
    end
  end
end
