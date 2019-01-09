# frozen_string_literal: true

require 'jwe'
require 'jwt'

module Castle
  class Middleware
    # Defines handlers for request/response scenarios. These all return
    # a rack friendly response or nil
    module Handler
      # Verification token returned by the challenge server, used for checking
      # if challenge has been solved
      PRM_VERIFICATION_TOKEN = '_cvt'

      # Saved data from the original response upon eg. a successful login
      # Used later to replay the request when a challenge has been solved
      PRM_CASTLE_REQUEST_DATA = '_crd'

      # Solve challenge
      module Challenge
        class << self
          def call(req)
            api_url = ENV.fetch('CASTLE_VERIFY_API', 'http://localhost:9292')
            if req.params.key?(PRM_VERIFICATION_TOKEN)
              uri = URI(api_url + '/confirm?t=' + req.params[PRM_VERIFICATION_TOKEN])
              res = Net::HTTP.get_response(uri)

              # TODO: how to handle error?

              headers = res.each_header.to_h.merge(
                'content-length' => res.body.size.to_s
              )
              headers.delete('transfer-encoding')

              response = Rack::Response.new(res.body, 200, headers)
              response.finish
            end
          end
        end
      end

      # Redirect to saved context
      module Redirect
        class << self
          def call(req)
            if req.params[PRM_CASTLE_REQUEST_DATA]
              # TODO: implement a proper format. We need to know if the data
              # was captured from the request or the response
              session_data, type = req.params[PRM_CASTLE_REQUEST_DATA].split(',')
              if type == 'request'
                # Decrypt
                key = ENV['CASTLE_API_SECRET'][0..15]
                plaintext = ::JWE.decrypt(session_data, key)
                backup_env = Marshal.load(plaintext)

                backup_env.each do |k,v|
                  if ['rack.input'].include?(k)
                    req.env[k] = StringIO.new(backup_env[k])
                  else
                    req.env[k] = v
                  end
                end
                return nil # fall through
              else # response
                # Decrypt
                key = ENV['CASTLE_API_SECRET'][0..15]
                plaintext = ::JWE.decrypt(session_data, key)
                return Marshal.load(plaintext)
              end
            end
          end
        end
      end

      # Capture request data and save for later while user is being challenged
      module RequestData
        # TODO: is this a complete list? Or maybe should instead specifiy
        # *unserializable* classes?
        SERIALIZABLE_CLASSES = [
          ActiveSupport::HashWithIndifferentAccess,
          Array,
          FalseClass,
          Hash,
          Integer,
          NilClass,
          String,
          Symbol,
          TrueClass,
        ].freeze

        class << self
          def call(req)
            # TODO: hardcoded profile update route
            if false # req.env['REQUEST_METHOD'] == 'POST' && req.env['REQUEST_PATH'] == '/'
              backup_env = {}

              req.env.each do |k,v|
                if SERIALIZABLE_CLASSES.include?(v.class)
                  backup_env[k] = v
                elsif ['rack.input'].include?(k) # StringIO, TODO: generalize
                  backup_env[k] = v.read
                  v.rewind
                end
              end

              # Encrypt
              key = ENV['CASTLE_API_SECRET'][0..15] # need to be 16 bytes
              payload = Marshal.dump(backup_env)
              redirect_data = JWE.encrypt(payload, key, alg: 'dir')+',request'  # XXX: hack

              # TODO: request_data should be transferred to Challenge handler, not bail here
              return [200, {
                'Content-Type' => 'text/html'
              }, ["<a href='http://localhost.charlesproxy.com:3000/?_crd=#{redirect_data}'>Proceed</a>"]]
            end
          end
        end
      end

      # Match a configured mapping and execute configured response handlers
      class Mapping
        extend Forwardable
        def_delegators :@middleware, :log, :configuration, :authenticate

        def initialize(middleware)
          @middleware = middleware
          @event_mapping = Castle::Middleware::EventMapper.build(configuration.events)
        end

        def call(req, path = nil, response = nil)
          path ||= req.path
          # Find a matching event from the config
          status, headers = response if response

          mapping = @event_mapping.find_by_rack_request(status.to_s, path, headers, req, true, response.nil?).first

          return if mapping.nil?

          resource = configuration.services.provide_user.call(req, true)

          return if resource.nil?
          if response
            body = case response[2]
            when String then response[2]
            when Array, Rack::BodyProxy
              if response[2].respond_to? :body
                response[2].body
              else
                response[2].first
              end
            end

            # Encrypt
            key = ENV['CASTLE_API_SECRET'][0..15] # need to be 16 bytes
            payload = Marshal.dump([response[0], response[1], body])
            redirect_data = ::JWE.encrypt(payload, key, alg: 'dir')
          end

          # get event properties from params
          event_properties = PropertiesProvide.call(req.params, mapping.properties)

          # get user_traits from params
          user_traits_from_params = PropertiesProvide.call(req.params, mapping.user_traits_from_params)

          verdict = process_authenticate(req, resource, mapping, user_traits_from_params, event_properties)

          # XXX: hack until we can retrive user email based on device token
          email = req.params.fetch('user', {})['email']
          referrer = req.env['HTTP_ORIGIN']

          response_from_verdict(verdict, mapping, redirect_data, email, referrer)
        end

        def response_from_verdict(verdict, mapping, redirect_data, email, referrer)
          case verdict[:action]
          when 'challenge'
            if mapping.challenge
              device_token = verdict[:device_token]

              if email
                payload = JWT.decode(device_token, ENV['CASTLE_API_SECRET'], 'HS256')[0]
                payload['email'] = email
                device_token = ::JWT.encode(payload, ENV['CASTLE_API_SECRET'], 'HS256')
              end

              # TODO: encode event name (or similar) so you can't solve a captcha for a different event and then use that token
              uri = URI("#{ENV.fetch('CASTLE_VERIFY_API', 'http://localhost:9292')}/v0/request")
              res = Net::HTTP.post_form(uri, {
                device_token: device_token,
                referrer: referrer
              })
              verification_token = JSON.parse(res.body)['verification_token']

              response = mapping_response(mapping.challenge, redirect_data, verification_token)

              return response
            end
          when 'deny'
            if mapping.deny
              return mapping_response(mapping.deny, redirect_data, verification_token)
            end
          end
        end

        def mapping_response(response, redirect_data, verification_token)
          status = response.status || 200
          if response.body
            [status, response.headers || {}, [response.body]]
          else
            uri = URI(response.url)

            res = Net::HTTP.post_form(uri, {})

            # Move these 2 "hacks" to the asset proxy
            # 1. Don't do GZIP
            headers =
              res.each_header.to_h.merge('content-length' => res.body.size.to_s)
            # 2. Avoid ERR_INVALID_CHUNKED_ENCODING
            headers.delete 'transfer-encoding'

            # Insert Castle meta tags
            res.body = insert_meta_tags(res.body, redirect_data, verification_token)

            response = Rack::Response.new res.body, status, response.headers || headers

            response.finish # finish writes out the response in the expected format.
          end
        end

        # TODO: extract to more robust module
        META_TAG = '<meta name="castle_%s" content="%s"></meta>'
        HEAD_END = '</head>'
        HEAD_REGEX = Regexp.new(HEAD_END, Regexp::IGNORECASE)
        def insert_meta_tags(response, redirect_data, verification_token)
          meta_tags = {
            session_data: redirect_data,
            verification_token: verification_token
          }.map { |k, v| META_TAG % ([k, CGI.escapeHTML(v)]) }
          .join("\n")

          (response.respond_to?(:body) ? response.body : response)
          .sub(HEAD_REGEX, "#{meta_tags}\n#{HEAD_END}" )
          end
        end

        def process_authenticate(req, resource, mapping, user_traits_from_params, event_properties)
          authenticate(
            Castle::Client.to_context(req),
            Castle::Client.to_options(
              user_id: Identification.id(resource, configuration.identify),
              user_traits: Identification.traits(
                resource, configuration.user_traits
              ).merge(user_traits_from_params),
              event: mapping.event,
              properties: event_properties
            )
          )
        end
      end
    end
  end
end
