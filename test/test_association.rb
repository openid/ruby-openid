require "test/unit"
require "openid/association"

module OpenID
  class AssociationTestCase < Test::Unit::TestCase
    def setup
      # Use this funny way of getting a time so that it does not have
      # fractional seconds, and so can be serialized exactly using our
      # standard code.
      issued = Time.at(Time.now.to_i)
      lifetime = 600

      @assoc = Association.new('handle', 'secret', issued,
                               lifetime, 'HMAC-SHA1')
    end

    def test_round_trip
      assoc2 = Association.deserialize(@assoc.serialize())
      [:handle, :secret, :lifetime, :assoc_type].each do |attr|
        assert_equal(@assoc.send(attr), assoc2.send(attr))
      end
    end

    def test_deserialize_failure
      field_list = Util.kv_to_seq(@assoc.serialize)
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

    def test_expires_in
      # Allow one second of slop
      assert(@assoc.expires_in.between?(599,600))
      assert(@assoc.expires_in(Time.now.to_i).between?(599,600))
    end

    def test_from_expires_in
      start_time = Time.now
      expires_in = @assoc.expires_in
      assoc = Association.from_expires_in(expires_in,
                                          @assoc.handle,
                                          @assoc.secret,
                                          @assoc.assoc_type)

      # Allow one second of slop here for code execution time
      assert_in_delta(1, assoc.expires_in, @assoc.expires_in)
      [:handle, :secret, :assoc_type].each do |attr|
        assert_equal(@assoc.send(attr), assoc.send(attr))
      end

      # Make sure the issued time is near the start
      assert(assoc.issued >= start_time)
      assert_in_delta(1, assoc.issued.to_f, start_time.to_f)
    end
  end
end
