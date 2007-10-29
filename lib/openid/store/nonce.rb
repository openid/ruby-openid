require 'openid/cryptutil'
require 'date'

module OpenID
  module Nonce
    SKEW = 60*60*5
    TIME_FMT = '%Y-%m-%dT%H:%M:%SZ'
    TIME_STR_LEN = '0000-00-00T00:00:00Z'.size
    @@NONCE_CHRS = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

    TIME_VALIDATOR = /\d\d\d\d-\d\d-\d\dT\d\d:\d\d:\d\dZ/

    # Extract timestamp from a nonce string
    def split_nonce(nonce_str)
      timestamp_str = nonce_str[0...TIME_STR_LEN]
      raise ArgumentError if timestamp_str.size < TIME_STR_LEN
      raise ArgumentError unless timestamp_str.match(TIME_VALIDATOR)
      ts = Time.parse(timestamp_str).to_i
      raise ArgumentError if ts < 0
      return ts, nonce_str[TIME_STR_LEN..-1]
    end

    # Is the timestamp that is part of the specified nonce string
    # within the allowed clock-skew of the current time?
    def check_timestamp(nonce_str, allowed_skew=SKEW, now=nil)
      begin
        stamp, foo = split_nonce(nonce_str)
      rescue ArgumentError # bad timestamp
        return false
      end
      now = Time.now.to_i unless now

      # times before this are too old
      past = now - allowed_skew

      # times newer than this are too far in the future
      future = now + allowed_skew

      return (past <= stamp and stamp <= future)
    end

    # generate a nonce with the specified timestamp (defaults to now)
    def mk_nonce(time = nil)
      salt = CryptUtil::random_string(6, @@NONCE_CHRS)
      if time.nil?
        t = Time.now
      else
        t = Time.at(time).getutc
      end
      time_str = t.strftime(TIME_FMT)
      return time_str + salt
    end
    
  end
end
