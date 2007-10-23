require 'test/unit'
require 'openid/trustroot'

require "testutil"

class TrustRootTest < Test::Unit::TestCase
  def _test_sanity(case_, sanity, desc)
    tr = OpenID::TrustRoot::TrustRoot.parse(case_)
    if sanity == 'sane'
      assert(tr.sane?, [case_, desc])
      assert(OpenID::TrustRoot::TrustRoot.check_sanity(case_), [case_, desc])
    elsif sanity == 'insane'
      assert(!tr.sane?, [case_, desc])
      assert(!OpenID::TrustRoot::TrustRoot.check_sanity(case_), [case_, desc])
    else
      assert(tr.nil?, case_)
    end
  end

  def _test_match(trust_root, url, expected_match)
    tr = OpenID::TrustRoot::TrustRoot.parse(trust_root)
    actual_match = tr.validate_url(url)
    if expected_match
      assert(actual_match, [trust_root, url])
      assert(OpenID::TrustRoot::TrustRoot.check_url(trust_root, url))
    else
      assert(!actual_match, [expected_match, actual_match, trust_root, url])
      assert(!OpenID::TrustRoot::TrustRoot.check_url(trust_root, url))
    end
  end

  def test_trustroots
    data = read_data_file('trustroot.txt', false)

    parts = data.split('=' * 40 + "\n").collect { |i| i.strip() }
    assert(parts[0] == '')
    _, ph, pdat, mh, mdat = parts

    getTests(['bad', 'insane', 'sane'], ph, pdat).each { |tc|
      sanity, desc, case_ = tc
      _test_sanity(case_, sanity, desc)
    }

    getTests([true, false], mh, mdat).each { |tc|
      match, desc, case_ = tc
      trust_root, url = case_.split()
      _test_match(trust_root, url, match)
    }
  end

  def getTests(grps, head, dat)
    tests = []
    top = head.strip()
    gdat = dat.split('-' * 40 + "\n").collect { |i| i.strip() }
    assert(gdat[0] == '')
    assert(gdat.length == (grps.length * 2 + 1), [gdat, grps])
    i = 1
    grps.each { |x|
      n, desc = gdat[i].split(': ')
      cases = gdat[i + 1].split("\n")
      assert(cases.length == n.to_i, "Number of cases differs from header count")
      cases.each { |case_|
        tests += [[x, top + ' - ' + desc, case_]]
      }
      i += 2
    }

    return tests
  end
end
