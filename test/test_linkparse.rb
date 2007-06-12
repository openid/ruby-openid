require 'test/unit'

require "openid/parse"

class LinkParseTestCase < Test::Unit::TestCase

  def test_bad
    cases = <<EOF
    <foo>

    <><barf

    not even html

    <link>

    <html>
    <link>

    <head>
    <link>

    <html>
    <head>
    </head>
    <link>

    <html>
    <link>
    <head>

    <link>
    <html>
    <head>

    <html>
    <head>
    </head>
    </html>
    <link>

    <html>
    <head>
    <html>
    <link>

    <head>
    <html>
    <link>

    <html>
    <head>
    <body>
    <link>

    <html>
    <head>
    <head>
    <link>

    <html>
    <head>
    <script>
    <link>
    </script>

    <html>
    <head>
    <!--
    <link>
    -->

    <html>
    <head>
    <![CDATA[
    <link>
    ]]>

    <html>
    <head>
    <![cDaTa[
    <link>
    ]]>

    <htmlx>
    <head>
    <link>

    <html:summer>
    <head>
    <link>

    <html>
    <head:zucchini>
    <link>

    <html/>
    <head>
    <link>

    <html/>
    <html>
    <head>
    <link>

    <html>
    <head/>
    <link>

    <html>
    <head/>
    <head>
    <link>

    <!-- Plain vanilla -->
    <html>
    <head>
    <link>

    <!-- Ignore tags in the <script:... > namespace -->
    <html>
    <head>
    <script:paddypan>
    <link>
    </script:paddypan>

    <!-- Short link tag -->
    <html>
    <head>
    <link/>

    <!-- Spaces in the HTML tag -->
    <html >
    <head>
    <link>

    <!-- Spaces in the head tag -->
    <html>
    <head >
    <link>

    <html>
    <head>
    <link >

    <html><head><link>

    <html>
    <head>
    <link>
    </head>

    <html>
    <head>
    <link>
    </head>
    <link>

    <html>
    <head>
    <link>
    <body>
    <link>

    <html>
    <head>
    <link>
    </html>

    <html>
    <head>
    <link>
    </html>
    <link>

    <html>
    <delicata>
    <head>
    <title>
    <link>

    <HtMl>
    <hEaD>
    <LiNk>

    <butternut>
    <html>
    <summer>
    <head>
    <turban>
    <link>

    <html>
    <head>
    <script>
    <link>

    <html><head><script><link>

    <html>
    <head>
    <!--
    <link>

    <html>
    <head>
    <![CDATA[
    <link>

    <html>
    <head>
    <![ACORN[
    <link>
    ]]>

    <html>
    <head>
    <link>

    <html>
    <head>
    <link>
    <link>

    <html>
    <gold nugget>
    <head>
    <link>
    <link>

    <html>
    <head>
    <link>
    <LiNk>
    <body>
    <link>
EOF


    results = []
    cases.split("\n\n").each do |c|
      parse_link_attrs(c){ |x| results << x }
    end

    results.each {|r| assert(r == {}, r.to_s)}
  end

  def test_good_rel
    cases = [
             "<html><head><link rel=openid.server>",             
             "<html><head><link rel=openid.server />",
             "<html><head><link hubbard rel=openid.server>",
             "<html><head><link hubbard rel=openid.server></link>",
             "<html><head><link hubbard rel=openid.server />",
             "<html><head><link / rel=openid.server>",
             "<html><head><link rel='openid.server'>"
            ]
    
    results = []
    cases.each do |c|
      parse_link_attrs(c) { |x| results << x }
    end

    assert_equal(cases.length, results.length)
    results.each { |x| assert(x["rel"] == "openid.server", x["rel"]) }
  end

  def test_good
    lj_test = <<EOF
<!DOCTYPE html
          PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN"
                 "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
                 <html xmlns="http://www.w3.org/1999/xhtml">
                   <head>
                     <link rel="stylesheet" href="http://www.livejournal.com/~serotta/res/319998/stylesheet?1130478711" type="text/css" />
         <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
 <meta name="foaf:maker" content="foaf:mbox_sha1sum '12f8abdacb5b1a806711e23249da592c0d316260'" />
 <meta name="robots" content="noindex, nofollow, noarchive" />
 <meta name="googlebot" content="nosnippet" />
 <link rel="openid.server" href="http://www.livejournal.com/openid/server.bml" />
                   <title>Brian</title>
         </head>
EOF
    cases = [
             ["<html><head><link rel=\"openid.server\" href=\"http://www.myopenid.com/server\" /></head></html>", [{"rel"=>"openid.server","href"=>"http://www.myopenid.com/server"}]],
###
             ["<html><head><link rel='openid.server' href='http://www.myopenid.com/server' /><link rel='openid.delegate' href='http://example.myopenid.com/' /></head></html>",
              [{"rel"=>"openid.server","href"=>"http://www.myopenid.com/server"},
               {"rel"=>"openid.delegate","href"=>"http://example.myopenid.com/"}]],
###
             [lj_test,
              [{"rel"=>"stylesheet","type"=>"text/css","href"=>"http://www.livejournal.com/~serotta/res/319998/stylesheet?1130478711"},
               {"rel"=>"openid.server","href"=>"http://www.livejournal.com/openid/server.bml"}]]

         ]

    cases.each do |unparsed, expected|
      actual = []
      parse_link_attrs(unparsed) {|x| actual << x}
      assert_equal(expected, actual)
    end

  end

end
