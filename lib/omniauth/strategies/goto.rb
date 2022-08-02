require 'omniauth-oauth2'

module OmniAuth
  module Strategies
    class GoTo < OmniAuth::Strategies::OAuth2

      args %i[client_id client_secret]

      option :name, 'goto'

      option :client_options, {
        site: "https://api.getgo.com",
        authorize_url: "https://api.getgo.com/oauth/v2/authorize",
        token_url: "https://api.getgo.com/oauth/v2/token",
        response_type: 'code',
      }

      option :auth_token_params, {
        grant_type: 'authorization_code',
      }

      # When `true`, client_id and client_secret are returned in extra['raw_info'].
      option :extra_client_id_and_client_secret, false

      # Store response
      attr_accessor :token_response

      def authorize_params
        super.tap do |params|
          %w[client_options].each do |v|
            if request.params[v]
              params[v.to_sym] = request.params[v]
            end
          end
        end
      end

      def build_access_token
        verifier = request.params["code"]
        # Override regular client when using setup: proc
        if env['omniauth.params']['client_id'] && env['omniauth.params']['client_secret']
          client = ::OAuth2::Client.new(
            env['omniauth.params']['client_id'],
            env['omniauth.params']['client_secret'],
            authorize_url: options.client_options.authorize_url,
            token_url: options.client_options.token_url
          )
          @token_response = client.auth_code.get_token(verifier, {:redirect_uri => callback_url}.merge(token_params.merge!(headers: {'Authorization' => basic_auth_header(env['omniauth.params']['client_id'], env['omniauth.params']['client_secret']) }).to_hash(:symbolize_keys => true)), deep_symbolize(options.auth_token_params))
        else
          super
        end
      end

      uid { raw_info["account_key"] }

      extra do
        { raw_info: raw_info }
      end

      def raw_info
        @raw_info ||= begin
          hash = @token_response.params.slice('account_key', 'account_type', 'email', 'firstName', 'lastName', 'organizer_key', 'version')
          hash.merge!({ client_id: smart_client_id, client_secret: smart_client_secret }) if options[:extra_client_id_and_client_secret]
          hash
        end
      end

      def smart_client_id
        @smart_client_id ||= env['omniauth.params']['client_id'] || env['omniauth.strategy'].options.client_id
      end

      def smart_client_secret
        @smart_client_secret ||= env['omniauth.params']['client_secret'] || env['omniauth.strategy'].options.client_secret
      end

      def callback_url
        full_host + script_name + callback_path
      end

      def basic_auth_header(client_id, client_secret)
        "Basic " + Base64.strict_encode64("#{client_id}:#{client_secret}")
      end
    end
  end
end

OmniAuth.config.add_camelization 'goto', 'GoTo'
OmniAuth.config.add_camelization 'go_to', 'GoTo'