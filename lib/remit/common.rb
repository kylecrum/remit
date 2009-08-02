require 'base64'
require 'erb'
require 'uri'

require 'rubygems'
require 'relax'

module Remit
  class Request < Relax::Request
    def self.action(name)
      parameter :action, :value => name
    end

    def convert_key(key)
      key.to_s.gsub(/(^|_)(.)/) { $2.upcase }.to_sym
    end
    protected :convert_key
  end

  class BaseResponse < Relax::Response
    def node_name(name, namespace=nil)
      super(name.to_s.gsub(/(^|_)(.)/) { $2.upcase }, namespace)
    end
  end

  class Response < BaseResponse
    parameter :request_id

    attr_accessor :status
    attr_accessor :errors

    def initialize(xml)
      super

      if is?(:Response) && has?(:Errors)
        @errors = elements(:Errors).collect do |error|
          Error.new(error)
        end
      else
        @status = text_value(element(:Status))
        @errors = elements('Errors/Errors').collect do |error|
          ServiceError.new(error)
        end unless successful?
      end
    end

    def successful?
      @status == ResponseStatus::SUCCESS
    end

    def node_name(name, namespace=nil)
      super(name.to_s.split('/').collect{ |tag|
        tag.gsub(/(^|_)(.)/) { $2.upcase }
      }.join('/'), namespace)
    end
  end

  #do we really need to pass in a uri and query params?  Can't we just pass in the uri?
  class SignedQuery < Relax::Query
    def initialize(uri, secret_key, query={})
      super(query)
      @uri = URI.parse(uri.to_s)
      parse_uri #values in the uri take precedence over the ones in the query
      @secret_key = secret_key
    end

    def sign
      delete(signature_key)
      store(signature_key, signature)
    end

    def to_s(signed=true)
      sign if signed
      super()
    end
    
    def signature
      self.class.signature(@secret_key,self)
    end
    
    def signature_key
      :awsSignature
    end
    
    def parse_uri
      if @uri.query
        @uri.query.split('&').each do |parameter|
          key, value = parameter.split('=', 2)
          self[key] = self.class.unescape_value(value)
        end
      end
    end
    private :parse_uri

    class << self
      
      def signature(secret_key,hashable = {})
        keys = hashable.keys.sort { |a, b| a.to_s.downcase <=> b.to_s.downcase }

        signature = keys.inject('') do |signature, key|
          value = hashable[key]
          signature += key.to_s + value.to_s if value
        end

        Base64.encode64(OpenSSL::HMAC.digest(OpenSSL::Digest::SHA1.new, secret_key, signature)).strip
      end
    end
  end
end
