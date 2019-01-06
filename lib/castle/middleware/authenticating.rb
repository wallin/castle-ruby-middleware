# frozen_string_literal: true

require 'castle/middleware/identification'
require 'castle/middleware/event_mapper'
require 'castle/middleware/properties_provide'
require 'castle/middleware/handler'

module Castle
  class Middleware
    class Authenticating
      attr_reader :app

      def initialize(app)
        @app = app
        @mapping_handler = Handler::Mapping.new(Middleware.instance)
      end

      def call(env)
        req = Rack::Request.new(env)

        # preserve state of path
        path = req.path

        # Run Castle handlers
        result = [
          @mapping_handler, # Before-handlers
          Handler::RequestData,
          Handler::Challenge,
          Handler::Redirect
        ].reduce(nil) { |memo, handler| memo || handler.call(req) }

        return result if result

        # Call origin
        app_result = app.call(env)
        return app_result if app_result.nil?

        # Run after-handlers
        @mapping_handler.call(req, path, app_result) || app_result
      end
    end
  end
end
