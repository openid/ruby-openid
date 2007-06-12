require 'test/unit'
require 'fileutils'
require 'pathname'
require 'tmpdir'

require 'openid/filestore'
require 'storetestcase'

class FileStoreTestCase < Test::Unit::TestCase
  include StoreTestCase

  @@dir = Pathname.new(Dir.tmpdir).join('filstoretest')

  def setup
    FileUtils.rm_rf(@@dir)
    @store = OpenID::FilesystemStore.new(@@dir)    
  end

  def teardown
    FileUtils.rm_rf(@@dir)
  end
end

class DumbStoreTestCase < Test::Unit::TestCase
  include StoreTestCase

  def setup
    @store = OpenID::DumbStore.new('unit-test')
  end

  def test_nonce
    assert_equal(true, @store.use_nonce('anything'))
  end

end

class MemoryStoreTestCase < Test::Unit::TestCase
  include StoreTestCase

  @@dir = Pathname.new(Dir.tmpdir).join('filstoretest')

  def setup
    @store = OpenID::MemoryStore.new
  end

end

