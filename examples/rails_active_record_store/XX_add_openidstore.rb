class AddOpenidstore < ActiveRecord::Migration
  def self.up
    create_table :openid_settings do |t|
      t.column :setting, :string
      t.column :value, :binary
    end

    create_table :openid_associations do |t|
      # server_url is blob, because URLs could be longer
      # than db can handle as a string
      t.column :server_url, :binary
      t.column :handle,     :string
      t.column :secret,     :binary
      t.column :issued,     :integer
      t.column :lifetime,   :integer
      t.column :assoc_type, :string
    end

    create_table :openid_nonces do |t|
      t.column :nonce,   :string
      t.column :created, :integer
    end
  end

  def self.down
    drop_table :openid_settings
    drop_table :openid_associations
    drop_table :openid_nonces
  end
end
