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

