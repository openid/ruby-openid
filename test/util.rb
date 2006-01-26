require 'test/unit'

require "openid/util"

class UtilTestCase < Test::Unit::TestCase

  def test_rand
    max = 155172898181473697471232257763715539915724801966915404479707795314057629378541917580651227423698188993727816152646631438561595825688188889951272158842675419950341258706556549803580104870537681476726513255747040765857479291291572334510643245094715007229621094194349783925984760375594985848253359305585439638443
    r = OpenID::Util.rand(max)
    assert(r < max)
    assert(r >= 0)
  end

  def test_kvform
    kv = {
      "foo" => "bar",
      "baz" => "hat:pants"
    }
    
    parsed = OpenID::Util.kvform(kv)
    unparsed = OpenID::Util.parsekv(parsed)
    assert(kv == unparsed)
  end

  def test_packing
    cases = [1,2,4305783490578, 457092437545247574732543905702435734958]
    cases.each { |c| assert(c == OpenID::Util.str_to_num(OpenID::Util.num_to_str(c))) }
  end

  def test_base64
    cases = [
             "",
             "\000",
             "\001",
             "\000" * 100,
             OpenID::Util.random_string(100),
            ]

    cases.each do |c|
      encoded = OpenID::Util.to_base64(c)
      decoded = OpenID::Util.from_base64(encoded)
      assert(c == decoded)
    end
      
  end

  def test_shortcuts
    max = 155172898181473697471232257763715539915724801966915404479707795314057629378541917580651227423698188993727816152646631438561595825688188889951272158842675419950341258706556549803580104870537681476726513255747040765857479291291572334510643245094715007229621094194349783925984760375594985848253359305585439638443
    x = 5646357865294356435623409524357247359023479579052473
    assert_equal(x, OpenID::Util.base64_to_num(OpenID::Util.num_to_base64(x)))
    assert_equal(max, OpenID::Util.base64_to_num(OpenID::Util.num_to_base64(max)))
  end

end


