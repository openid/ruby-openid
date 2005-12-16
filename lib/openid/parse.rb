require "html/htmltokenizer"

def parseLinkAttrs(data)
  parser = HTMLTokenizer.new(data)
  while el = parser.getTag('link', 'body')
    if el.tag_name == 'link'
      yield el.attr_hash
    elsif el.tag_name == 'body'
      return
    end
  end  
end

            
            
