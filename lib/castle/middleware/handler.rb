

module Castle
  class Middleware
    # Defines handlers for request/response scenarios. These all return
    # a rack friendly response or nil
    module Handler
      # Solve challenge
      module Challenge
        class << self
          def call(req)
            api_url = ENV.fetch('CASTLE_VERIFY_API', 'http://localhost:9292')
            if req.params.key?('_cvt')
              uri = URI(api_url + '/confirm?t=' + req.params['_cvt'])
              res = Net::HTTP.get_response(uri)

              # TODO: how to handler error?

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
            if req.params['_crd']
              return JSON.load(Base64.urlsafe_decode64(req.params['_crd']))
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
            # TODO: needed?
            body = if !response[2].is_a? String
              response[2].body
            else
              response[2]
            end
            redirect_data = Base64.urlsafe_encode64([response[0], response[1], body].to_json)
          end

          # get event properties from params
          event_properties = PropertiesProvide.call(req.params, mapping.properties)

          # get user_traits from params
          user_traits_from_params = PropertiesProvide.call(req.params, mapping.user_traits_from_params)

          verdict = process_authenticate(req, resource, mapping, user_traits_from_params, event_properties)

          # XXX: hack until we can retrive user email based on device token
          email = req.params['user']['email']
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
                device_token = JWT.encode(payload, ENV['CASTLE_API_SECRET'], 'HS256')
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

            res = Net::HTTP.post_form(uri, {
              verification_token: verification_token,
              redirect_data: redirect_data })

            # Move these 2 "hacks" to the asset proxy
            # 1. Don't do GZIP
            headers =
              res.each_header.to_h.merge('content-length' => res.body.size.to_s)
            # 2. Avoid ERR_INVALID_CHUNKED_ENCODING
            headers.delete 'transfer-encoding'

            response = Rack::Response.new res.body, status, response.headers || headers

            response.finish # finish writes out the response in the expected format.
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
