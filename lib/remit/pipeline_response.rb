module Remit
  class PipelineResponse
    def initialize(uri, secret_key)
      @uri        = URI.parse(uri)
      @secret_key = secret_key
    end

    # Returns +true+ if the response is correctly signed (awsSignature).
    #
    #--
    # The unescape_value method is used here because the awsSignature value
    # pulled from the request is filtered through the same method.
    #++
    def valid?
      return false unless given_signature
      #unescape both sides.  now it will work even if the given_signature is escaped
      Relax::Query.unescape_value(correct_signature) == Relax::Query.unescape_value(given_signature)
    end

    # Returns +true+ if the response returns a successful state.
    def successful?
      [
        Remit::PipelineStatusCode::SUCCESS_ABT,
        Remit::PipelineStatusCode::SUCCESS_ACH,
        Remit::PipelineStatusCode::SUCCESS_CC,
        Remit::PipelineStatusCode::SUCCESS_RECIPIENT_TOKEN_INSTALLED
      ].include?(request_query[:status])
    end
    
    def [](key)
      request_query[key]
    end

    def method_missing(method, *args) #:nodoc:
      if request_query.has_key?(method)
        request_query[method]
      else
        super
      end
    end
    
    def signature_key
      :awsSignature
    end

    def request_query(reload = false)
      @query ||= Remit::SignedQuery.new(@uri, @secret_key)
    end
    private :request_query

    def given_signature
      request_query[signature_key]
    end
    private :given_signature

    def correct_signature
      query_params = request_query.clone
      query_params.delete(signature_key)
      Remit::SignedQuery.signature(FPS_SECRET_KEY,query_params)
    end
    private :correct_signature
  end
end
