require 'rexml/document'
require 'rexml/element'

module OpenID
  module Yadis

    XRD_NS_2_0 = 'xri://$xrd*($v*2.0)'
    XRDS_NS = 'xri://$xrds'

    def Yadis::mkXRDSTag(name)
      e = REXML::Element.new('xrds:' + name)
      e.add_namespace('xrds', XRDS_NS)
      return e
    end

    ROOT_TAG = Yadis::mkXRDSTag('XRDS')

    class XRDSError < StandardError
    end

    def Yadis::parseXRDS(text)
      d = REXML::Document.new(text)
      if is_xrds?(d)
        return d
      else
        raise XRDSError.new("Not an XRDS document.")
      end
    end

    def Yadis::is_xrds?(xrds_tree)
      xrds_root = xrds_tree.root
      return (!xrds_root.nil? and
        xrds_root.name == ROOT_TAG.name and
        xrds_root.namespace == ROOT_TAG.namespace)
    end

    def Yadis::get_yadis_xrd(xrds_tree)
      xrds_tree.root.each_element('/xrds:XRDS/XRD[last()]') { |el|
        return el
      }
      raise XRDSError.new("No XRD element found.")
    end

    # aka iterServices in Python
    def Yadis::each_service(xrds_tree, &block)
      xrd = get_yadis_xrd(xrds_tree)
      xrd.each_element('Service', &block)
    end

    def Yadis::expand_service(service_element)
      es = service_element.elements
      uris = es.each('URI/text()')
      types = es.each('Type/text()')
      # REXML::Text objects are not strings.
      types = types.collect { |t| t.to_s }
      uris.collect { |uri| [types, uri.to_s, service_element] }
    end
  end
end
