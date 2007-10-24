
module OpenID

  module Util

    def Util.seqToKV(seq, strict=false)
      # Represent a sequence of pairs of strings as newline-terminated
      # key:value pairs. The pairs are generated in the order given.
      #
      # @param seq: The pairs
      #
      # returns a string representation of the sequence
      err = lambda { |msg|
        msg = "seqToKV warning: #{msg}: #{seq.inspect}"
        if strict
          raise ArgumentError, msg
        else
          Util.log(msg)
        end
      }

      lines = []
      seq.each { |k, v|
        if !k.is_a?(String)
          err.call("Converting key to string: #{k.inspect}")
          k = k.to_s
        end

        if !k.index("\n").nil?
          raise ArgumentError, "Invalid input for seqToKV: key contains newline: #{k.inspect}"
        end

        if !k.index(":").nil?
          raise ArgumentError, "Invalid input for seqToKV: key contains colon: #{k.inspect}"
        end

        if k.strip() != k
          err.call("Key has whitespace at beginning or end: #{k.inspect}")
        end

        if !v.is_a?(String)
          err.call("Converting value to string: #{v.inspect}")
          v = v.to_s
        end

        if !v.index("\n").nil?
          raise ArgumentError, "Invalid input for seqToKV: value contains newline: #{v.inspect}"
        end

        if v.strip() != v
          err.call("Value has whitespace at beginning or end: #{v.inspect}")
        end

        lines << k + ":" + v + "\n"
      }

      return lines.join("")
    end

    def Util.kvToSeq(data, strict=false)
      # After one parse, seqToKV and kvToSeq are inverses, with no
      # warnings:
      #
      # seq = kvToSeq(s)
      # seqToKV(kvToSeq(seq)) == seq
      err = lambda { |msg|
        msg = "kvToSeq warning: #{msg}: #{data.inspect}"
        if strict
          raise ArgumentError, msg
        else
          Util.log(msg)
        end
      }

      lines = data.split("\n")
      if data.length == 0
        return []
      end

      if data[-1].chr != "\n"
        err.call("Does not end in a newline")
        # We don't expect the last element of lines to be an empty
        # string because split() doesn't behave that way.
      end

      pairs = []
      line_num = 0
      lines.each { |line|
        line_num += 1

        # Ignore blank lines
        if line.strip() == ""
          next
        end

        pair = line.split(':', 2)
        if pair.length == 2
          k, v = pair
          k_s = k.strip()
          if k_s != k
            msg = "In line #{line_num}, ignoring leading or trailing whitespace in key #{k.inspect}"
            err.call(msg)
          end

          if k_s.length == 0
            err.call("In line #{line_num}, got empty key")
          end

          v_s = v.strip()
          if v_s != v
            msg = "In line #{line_num}, ignoring leading or trailing whitespace in value #{v.inspect}"
            err.call(msg)
          end

          pairs << [k_s, v_s]
        else
          err.call("Line #{line_num} does not contain a colon")
        end
      }

      return pairs
    end

    def Util.dictToKV(d)
      return seqToKV(d.entries.sort)
    end

    def Util.kvToDict(s)
      seq = kvToSeq(s)
      return Hash[*seq.flatten]
    end
  end
end
