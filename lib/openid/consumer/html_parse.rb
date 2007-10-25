require "openid/yadis/htmltokenizer"

module OpenID

  REFLAGS = Regexp::MULTILINE | Regexp::IGNORECASE | Regexp::EXTENDED

  # Stuff to remove before we start looking for tags
  REMOVED_RE = Regexp.compile('
    # Comments
    <!--.*?-->

    # CDATA blocks
  | <!\[CDATA\[.*?\]\]>

    # script blocks
  | <script\b

    # make sure script is not an XML namespace
    (?!:)

    [^>]*>.*?</script>

  ', REFLAGS, 'u')

  def openid_unescape(s)
    s.gsub('&amp;','&').gsub('&lt;','<').gsub('&gt;','>').gsub('&quot;','"')
  end

  def unescape_hash(h)
    newh = {}
    h.map{|k,v|
      newh[k]=openid_unescape(v)
    }
    newh
  end


  def OpenID.parse_link_attrs(html)
    stripped = html.gsub(REMOVED_RE,'')
    parser = HTMLTokenizer.new(stripped)

    links = []
    # to keep track of whether or not we are in the head element
    in_head = false
    in_html = false
    saw_head = false

    begin
      while el = parser.getTag('head', '/head', 'link', 'body', '/body', 
                               'html', '/html')
        
        # we are leaving head or have reached body, so we bail
        return links if ['/head', 'body', '/body', '/html'].member?(el.tag_name)

        # enforce html > head > link
        if el.tag_name == 'html'
          in_html = true
        end
        next unless in_html
        if el.tag_name == 'head'
          if saw_head
            return links #only allow one head
          end
          saw_head = true
          unless el.to_s[-2] == 47 # tag ends with a /: a short tag
            in_head = true
          end
        end
        next unless in_head

        return links if el.tag_name == 'html'

        if el.tag_name == 'link'
          links << unescape_hash(el.attr_hash)
        end
        
      end
    rescue RuntimeError # just stop parsing if there's an error
    end
    return links
  end
end

