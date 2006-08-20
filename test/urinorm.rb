require 'test/unit'
require "openid/urinorm"

class URINormTestCase < Test::Unit::TestCase

  def test_normalize
    lines = File.readlines('data/urinorm.txt')

    while lines.length > 0

      case_name = lines.shift.strip
      actual = lines.shift.strip
      expected = lines.shift.strip
      _newline = lines.shift

      if expected == 'fail'
        begin
          OpenID::Util::urinorm(actual)
        rescue URI::InvalidURIError
          assert true
        else
          raise 'Should have gotten URI error'
        end
      else
        normalized = OpenID::Util.urinorm(actual)
        assert_equal(expected, normalized, case_name)
      end
    end
  end

end

