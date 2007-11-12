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

    def Yadis::mkXRDTag(name)
      e = REXML::Element.new('xrd:' + name)
      e.add_namespace('xrd', XRD_NS_2_0)
      return e
    end

    ROOT_TAG = Yadis::mkXRDSTag('XRDS')
    CANONICALID_TAG = mkXRDTag('CanonicalID')

    class XRDSError < StandardError
    end

    def Yadis::parseXRDS(text)
      if text.nil?
        raise XRDSError.new("Not an XRDS document.")
      end

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

    def Yadis::services(xrds_tree)
      s = []
      each_service(xrds_tree) { |service|
        s << service
      }
      return s
    end

    def Yadis::expand_service(service_element)
      es = service_element.elements
      uris = es.each('URI') { |u| }
      uris = prio_sort(uris)
      types = es.each('Type/text()')
      # REXML::Text objects are not strings.
      types = types.collect { |t| t.to_s }
      uris.collect { |uri| [types, uri.text, service_element] }
    end

    # Sort a list of elements that have priority attributes.
    def Yadis::prio_sort(elements)
      elements.sort { |a,b|
        a.attribute('priority').to_s.to_i <=> b.attribute('priority').to_s.to_i
      }
    end
  end
end
