require 'test/unit'

require "openid/util"

class UtilTestCase < Test::Unit::TestCase

  def test_base64
    cases = [
             "",
             "\000",
             "\001",
             "\000" * 100,
             (0...256).collect{ |i| i.chr }.join('')
            ]

    cases.each do |c|
      encoded = OpenID::Util.to_base64(c)
      decoded = OpenID::Util.from_base64(encoded)
      assert(c == decoded)
    end

  end

  def test_append_args()
    simple = 'http://www.example.com/'

    cases = [
             ['empty list',
              [simple, []],
              simple],

             ['empty dict',
              [simple, {}],
              simple],

             ['one list',
              [simple, [['a', 'b']]],
              simple + '?a=b'],

             ['one dict',
              [simple, {'a' => 'b'}],
              simple + '?a=b'],

             ['two list (same)',
              [simple, [['a', 'b'], ['a', 'c']]],
              simple + '?a=b&a=c'],

             ['two list',
              [simple, [['a', 'b'], ['b', 'c']]],
              simple + '?a=b&b=c'],

             ['two list (order)',
              [simple, [['b', 'c'], ['a', 'b']]],
              simple + '?b=c&a=b'],

             ['two dict [order]',
              [simple, {'b' => 'c', 'a' => 'b'}],
              simple + '?a=b&b=c'],

             ['args exist [empty]',
              [simple + '?stuff=bother', []],
              simple + '?stuff=bother'],

             ['escape',
              [simple, [['=', '=']]],
              simple + '?%3D=%3D'],

             ['escape [URL]',
              [simple, [['this_url', simple]]],
              simple + '?this_url=http%3A%2F%2Fwww.example.com%2F'],

             ['use dots',
              [simple, [['openid.stuff', 'bother']]],
              simple + '?openid.stuff=bother'],

             ['args exist',
              [simple + '?stuff=bother', [['ack', 'ack']]],
              simple + '?stuff=bother&ack=ack'],

             ['args exist',
              [simple + '?stuff=bother', [['ack', 'ack']]],
              simple + '?stuff=bother&ack=ack'],

             ['args exist [dict]',
              [simple + '?stuff=bother', {'ack' => 'ack'}],
              simple + '?stuff=bother&ack=ack'],

             ['args exist [dict 2]',
              [simple + '?stuff=bother', {'ack' => 'ack', 'zebra' => 'lion'}],
              simple + '?stuff=bother&ack=ack&zebra=lion'],

             ['three args [dict]',
              [simple, {'stuff' => 'bother', 'ack' => 'ack', 'zebra' => 'lion'}],
              simple + '?ack=ack&stuff=bother&zebra=lion'],

             ['three args [list]',
              [simple, [['stuff', 'bother'], ['ack', 'ack'], ['zebra', 'lion']]],
              simple + '?stuff=bother&ack=ack&zebra=lion'],
            ]

    cases.each { |name, args, expected|
      url, pairs = args
      actual = OpenID::Util.append_args(url, pairs)
      msg = "[#{name}] Expected: #{expected}, actual: #{actual}"
      assert_equal(expected, actual, msg)
    }

  end

end
