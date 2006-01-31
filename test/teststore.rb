require 'test/unit'
require 'fileutils'

require 'openid/util'
require 'openid/filestore'
require 'openid/association'

require 'storetestcase'

class FileStoreTestCase < Test::Unit::TestCase
  include StoreTestCase

  @@dir = "/tmp/filstoretest"

  def setup
    FileUtils.rm_rf(@@dir)
    @store = OpenID::FilesystemOpenIDStore.new(@@dir)    
  end

  def teardown
    FileUtils.rm_rf(@@dir)
  end
end

