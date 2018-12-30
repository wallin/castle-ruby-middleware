# frozen_string_literal: true

require 'castle/middleware/identification'
require 'castle/middleware/event_mapper'
require 'castle/middleware/properties_provide'

module Castle
  class Middleware

    # TODO: convert to key value store
    API = {
      backup_env: nil
    }

    class Authenticating
      extend Forwardable
      def_delegators :@middleware, :log, :configuration, :authenticate

      attr_reader :app

      def initialize(app)
        @app = app
        @middleware = Middleware.instance
        @event_mapping = Castle::Middleware::EventMapper.build(configuration.events)
      end

      def call(env)
        req = Rack::Request.new(env)

        # preserve state of path
        path = req.path

        # Solve challenge
        if req.params['challenge_succeeded'] == '1'
          API[:backup_env].each do |k,v|
            if ['rack.input'].include?(k)
              env[k] = StringIO.new(API[:backup_env][k])
            else
              env[k] = v
            end
          end

        # TODO: Challenge all non-GET requests until config supports pre-request
        elsif env['REQUEST_METHOD'] != 'GET'
          serializable_classes = [TrueClass, FalseClass, NilClass, Symbol, Array, Hash, String, Integer, ActiveSupport::HashWithIndifferentAccess]
          API[:backup_env] = {}
          dropped_env = {}

          env.each do |k,v|
            if serializable_classes.include?(v.class)
              API[:backup_env][k] = v
            elsif ['rack.input'].include?(k)
              API[:backup_env][k] = v.read # StringIO
              v.rewind
            else
              dropped_env[k] = v
            end
          end

          # TODO: call handle_mapping_response instead
          uri = URI('https://brissmyr.github.io/pages/challenge.html')
          res = Net::HTTP.get_response(uri)
          headers =
            res.each_header.to_h.merge('content-length' => res.body.size.to_s)
          return [200, headers, [res.body]]
        end

        app_result = app.call(env)
        status, headers = app_result
        return app_result if app_result.nil?

        # Find a matching event from the config
        mapping = @event_mapping.find_by_rack_request(status.to_s, path, headers, req, true).first

        return app_result if mapping.nil?

        resource = configuration.services.provide_user.call(req, true)

        return app_result if resource.nil?

        # get event properties from params
        event_properties = PropertiesProvide.call(req.params, mapping.properties)

        # get user_traits from params
        user_traits_from_params = PropertiesProvide.call(req.params, mapping.user_traits_from_params)

        verdict = process_authenticate(req, resource, mapping, user_traits_from_params, event_properties)

        # if mapping.challenge
        #   redirect_result = authentication_verdict(verdict, req, resource)
        #   if redirect_result
        #     return [302, {
        #       'Location' => redirect_result,
        #       'Content-Type' => 'text/html',
        #       'Content-Length' => '0'
        #     }, []]
        #   end
        # end

        case verdict[:action]
        when 'challenge'
          if mapping.challenge
            return handle_mapping_response(mapping.challenge)
          end
        when 'deny'
          if mapping.deny
            return handle_mapping_response(mapping.deny)
          end
        end

        app_result
      end

      def handle_mapping_response(response)
        status = response.status || 200
        if response.body
          [status, response.headers || {}, [response.body]]
        else
          uri = URI(response.url)
          res = Net::HTTP.get_response(uri)

          # Don't do GZIP
          headers =
            res.each_header.to_h.merge('content-length' => res.body.size.to_s)

          [status, response.headers || headers, [res.body]]
        end
      end

      private

      def authentication_verdict(verdict, req, resource)
        case verdict[:action]
        when 'challenge' then challenge(req, resource)
        when 'deny' then deny(req, resource)
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

      def challenge(req, resource)
        return unless configuration.services.challenge

        configuration.services.challenge.call(req, resource)
      end

      def deny(req, resource)
        return unless configuration.services.deny

        configuration.services.deny.call(req, resource)
      end
    end
  end
end
