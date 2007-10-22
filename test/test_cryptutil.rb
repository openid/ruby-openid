require 'test/unit'
require "openid/cryptutil"

class CryptUtilTestCase < Test::Unit::TestCase
  BIG = 2 ** 256

  def test_rand
    # If this is not true, the rest of our test won't work
    assert(BIG.is_a?(Bignum))

    # It's possible that these will be small enough for fixnums, but
    # extraorindarily unlikely.
    a = OpenID::CryptUtil.rand(BIG)
    b = OpenID::CryptUtil.rand(BIG)
    assert(a.is_a?(Bignum))
    assert(b.is_a?(Bignum))
    assert_not_equal(a, b)
  end

  def test_rand_doesnt_depend_on_srand
    Kernel.srand(1)
    a = OpenID::CryptUtil.rand(BIG)
    Kernel.srand(1)
    b = OpenID::CryptUtil.rand(BIG)
    assert_not_equal(a, b)
  end

  def test_random_binary_convert
    (0..500).each do
      n = (0..10).inject(0) {|sum, element| sum + OpenID::CryptUtil.rand(BIG) }
      s = OpenID::CryptUtil.num_to_binary n
      assert(s.is_a?(String))
      n_converted_back = OpenID::CryptUtil.binary_to_num(s)
      assert_equal(n, n_converted_back)
    end
  end

  def test_enumerated_binary_convert
    {
        "\x00" => 0,
        "\x01" => 1,
        "\x7F" => 127,
        "\x00\xFF" => 255,
        "\x00\x80" => 128,
        "\x00\x81" => 129,
        "\x00\x80\x00" => 32768,
        "OpenID is cool" => 1611215304203901150134421257416556,
    }.each do |str, num|
      num_prime = OpenID::CryptUtil.binary_to_num(str)
      str_prime = OpenID::CryptUtil.num_to_binary(num)
      assert_equal(num, num_prime)
      assert_equal(str, str_prime)
    end
  end

  def with_n2b64
    test_dir = Pathname.new(__FILE__).dirname
    filename = test_dir.join('data', 'n2b64')
    File.open(filename) do |file|
      file.each_line do |line|
        base64, base10 = line.chomp.split
        yield base64, base10.to_i
      end
    end
  end

  def test_base64_to_num
    with_n2b64 do |base64, num|
      assert_equal(num, OpenID::CryptUtil.base64_to_num(base64))
    end
  end

  def test_num_to_base64
    with_n2b64 do |base64, num|
      assert_equal(base64, OpenID::CryptUtil.num_to_base64(num))
    end
  end
end
