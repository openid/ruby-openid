require "test/unit"
require "openid/association"

module OpenID
  class AssociationSerializationTestCase < Test::Unit::TestCase
    def test_round_trip
      # Use this funny way of getting a time so that it does not have
      # fractional seconds, and so can be serialized exactly using our
      # standard code.
      issued = Time.at(Time.now.to_i)
      lifetime = 600
      assoc = Association.new('handle', 'secret', issued,
                              lifetime, 'HMAC-SHA1')
      assoc2 = Association.deserialize(assoc.serialize())
      [:handle, :secret, :lifetime, :assoc_type].each do |attr|
        assert_equal(assoc.send(attr), assoc2.send(attr))
      end
    end

    def test_deserialize_failure
      field_list = [['version', '2'],
                    ['handle', 'x'],
                    ['secret', 'eA=='],
                    ['issued', '0'],
                    ['lifetime', '4'],
                    ['assoc_type', 'Cheese']]
      kv = Util.seq_to_kv(field_list + [['monkeys', 'funny']])
      assert_raises(StandardError) {
        Association.deserialize(kv)
      }

      bad_version_list = field_list.dup
      bad_version_list[0] = ['version', 'moon']
      bad_version_kv = Util.seq_to_kv(bad_version_list)
      assert_raises(StandardError) {
        Association.deserialize(bad_version_kv)
      }
    end
  end
end
